package com.termux.view

import android.annotation.SuppressLint
import android.content.ClipboardManager
import android.content.Context
import android.graphics.Canvas
import android.graphics.Typeface
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.text.InputType
import android.text.TextUtils
import android.util.AttributeSet
import android.view.*
import android.view.accessibility.AccessibilityManager
import android.view.autofill.AutofillValue
import android.view.inputmethod.BaseInputConnection
import android.view.inputmethod.EditorInfo
import android.view.inputmethod.InputConnection
import android.widget.Scroller
import androidx.annotation.RequiresApi
import com.termux.terminal.*
import com.termux.terminal.KeyHandler.getCode
import com.termux.view.textselection.TextSelectionCursorController
import kotlin.math.abs
import kotlin.math.roundToInt

/** View displaying and interacting with a [TerminalSession].  */
class TerminalView(context: Context, attributes: AttributeSet?) : View(context, attributes) {
    /** The currently displayed terminal session, whose emulator is [.mEmulator].  */
    var currentSession: TerminalSession? = null

    /** Our terminal emulator whose session is [.mTermSession].  */
    var mEmulator: TerminalEmulator? = null
    var mRenderer: TerminalRenderer? = null
    var mClient: TerminalViewClient? = null
    private var mTextSelectionCursorController: TextSelectionCursorController? = null
    private var mTerminalCursorBlinkerHandler: Handler? = null
    private var mTerminalCursorBlinkerRunnable: TerminalCursorBlinkerRunnable? = null
    private var mTerminalCursorBlinkerRate = 0
    private val mCursorInvisibleIgnoreOnce = false

    /** The top row of text to display. Ranges from -activeTranscriptRows to 0.  */
    var topRow = 0
    var mDefaultSelectors = intArrayOf(-1, -1, -1, -1)
    var mScaleFactor = 1f
    lateinit var mGestureRecognizer: GestureAndScaleRecognizer

    /** Keep track of where mouse touch event started which we report as mouse scroll.  */
    private var mMouseScrollStartX = -1
    private var mMouseScrollStartY = -1

    /** Keep track of the time when a touch event leading to sending mouse scroll events started.  */
    private var mMouseStartDownTime: Long = -1
    val mScroller = Scroller(context)

    /** What was left in from scrolling movement.  */
    var mScrollRemainder = 0f

    /** If non-zero, this is the last unicode code point received if that was a combining character.  */
    var mCombiningAccent = 0
    private val mAccessibilityEnabled: Boolean

    /**
     * @param client The [TerminalViewClient] interface implementation to allow
     * for communication between [TerminalView] and its client.
     */
    fun setTerminalViewClient(client: TerminalViewClient?) {
        mClient = client
    }

    /**
     * Sets whether terminal view key logging is enabled or not.
     *
     * @param value The boolean value that defines the state.
     */
    fun setIsTerminalViewKeyLoggingEnabled(value: Boolean) {
        TERMINAL_VIEW_KEY_LOGGING_ENABLED = value
    }

    /**
     * Attach a [TerminalSession] to this view.
     *
     * @param session The [TerminalSession] this view will be displaying.
     */
    fun attachSession(session: TerminalSession): Boolean {
        if (session === currentSession) return false
        topRow = 0
        currentSession = session
        mEmulator = null
        mCombiningAccent = 0
        updateSize()

        // Wait with enabling the scrollbar until we have a terminal to get scroll position from.
        isVerticalScrollBarEnabled = true
        return true
    }

    override fun onCreateInputConnection(outAttrs: EditorInfo): InputConnection? {
        if (mClient?.disableInput() == true) return null

        // Ensure that inputType is only set if TerminalView is selected view with the keyboard and
        // an alternate view is not selected, like an EditText. This is necessary if an activity is
        // initially started with the alternate view or if activity is returned to from another app
        // and the alternate view was the one selected the last time.
        if (mClient!!.isTerminalViewSelected) {
            if (mClient!!.shouldEnforceCharBasedInput) {
                // Some keyboards seems do not reset the internal state on TYPE_NULL.
                // Affects mostly Samsung stock keyboards.
                // https://github.com/termux/termux-app/issues/686
                // However, this is not a valid value as per AOSP since `InputType.TYPE_CLASS_*` is
                // not set and it logs a warning:
                // W/InputAttributes: Unexpected input class: inputType=0x00080090 imeOptions=0x02000000
                // https://cs.android.com/android/platform/superproject/+/android-11.0.0_r40:packages/inputmethods/LatinIME/java/src/com/android/inputmethod/latin/InputAttributes.java;l=79
                outAttrs.inputType = InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
            } else {
                // Using InputType.NULL is the most correct input type and avoids issues with other hacks.
                //
                // Previous keyboard issues:
                // https://github.com/termux/termux-packages/issues/25
                // https://github.com/termux/termux-app/issues/87.
                // https://github.com/termux/termux-app/issues/126.
                // https://github.com/termux/termux-app/issues/137 (japanese chars and TYPE_NULL).
                outAttrs.inputType = InputType.TYPE_NULL
            }
        } else {
            // Corresponds to android:inputType="text"
            outAttrs.inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_NORMAL
        }

        // Note that IME_ACTION_NONE cannot be used as that makes it impossible to input newlines using the on-screen
        // keyboard on Android TV (see https://github.com/termux/termux-app/issues/221).
        outAttrs.imeOptions = EditorInfo.IME_FLAG_NO_FULLSCREEN
        return object : BaseInputConnection(this, true) {
            override fun finishComposingText(): Boolean {
                if (TERMINAL_VIEW_KEY_LOGGING_ENABLED) mClient!!.logInfo(LOG_TAG, "IME: finishComposingText()")
                super.finishComposingText()
                sendTextToTerminal(editable.toString())
                editable?.clear()
                return true
            }

            override fun commitText(text: CharSequence, newCursorPosition: Int): Boolean {
                if (TERMINAL_VIEW_KEY_LOGGING_ENABLED) {
                    mClient!!.logInfo(LOG_TAG, "IME: commitText(\"$text\", $newCursorPosition)")
                }
                super.commitText(text, newCursorPosition)
                if (mEmulator == null) return true
                val content = editable
                sendTextToTerminal(content.toString())
                content?.clear()
                return true
            }

            override fun deleteSurroundingText(leftLength: Int, rightLength: Int): Boolean {
                if (TERMINAL_VIEW_KEY_LOGGING_ENABLED) {
                    mClient!!.logInfo(LOG_TAG, "IME: deleteSurroundingText($leftLength, $rightLength)")
                }
                // The stock Samsung keyboard with 'Auto check spelling' enabled sends leftLength > 1.
                val deleteKey = KeyEvent(KeyEvent.ACTION_DOWN, KeyEvent.KEYCODE_DEL)
                for (i in 0 until leftLength) sendKeyEvent(deleteKey)
                return super.deleteSurroundingText(leftLength, rightLength)
            }

            fun sendTextToTerminal(text: CharSequence) {
                stopTextSelectionMode()
                val textLengthInChars = text.length
                var i = 0
                while (i < textLengthInChars) {
                    val firstChar = text[i]
                    var codePoint: Int
                    codePoint = if (Character.isHighSurrogate(firstChar)) {
                        if (++i < textLengthInChars) {
                            Character.toCodePoint(firstChar, text[i])
                        } else {
                            // At end of string, with no low surrogate following the high:
                            TerminalEmulator.UNICODE_REPLACEMENT_CHAR
                        }
                    } else {
                        firstChar.code
                    }

                    // Check onKeyDown() for details.
                    if (mClient!!.readShiftKey()) codePoint = codePoint.toChar().uppercaseChar().code
                    var ctrlHeld = false
                    if (codePoint <= 31 && codePoint != 27) {
                        if (codePoint == '\n'.code) {
                            // The AOSP keyboard and descendants seems to send \n as text when the enter key is pressed,
                            // instead of a key event like most other keyboard apps. A terminal expects \r for the enter
                            // key (although when icrnl is enabled this doesn't make a difference - run 'stty -icrnl' to
                            // check the behaviour).
                            codePoint = '\r'.code
                        }

                        // E.g. penti keyboard for ctrl input.
                        ctrlHeld = true
                        when (codePoint) {
                            31 -> codePoint = '_'.code
                            30 -> codePoint = '^'.code
                            29 -> codePoint = ']'.code
                            28 -> codePoint = '\\'.code
                            else -> codePoint += 96
                        }
                    }
                    inputCodePoint(KEY_EVENT_SOURCE_SOFT_KEYBOARD, codePoint, ctrlHeld, false)
                    i++
                }
            }
        }
    }

    override fun computeVerticalScrollRange(): Int {
        return if (mEmulator == null) 1 else mEmulator!!.screen.activeRows
    }

    override fun computeVerticalScrollExtent(): Int {
        return if (mEmulator == null) 1 else mEmulator!!.mRows
    }

    override fun computeVerticalScrollOffset(): Int {
        return if (mEmulator == null) 1 else mEmulator!!.screen.activeRows + topRow - mEmulator!!.mRows
    }

    @JvmOverloads
    fun onScreenUpdated(skipScrolling: Boolean = false) {
        var skipScr = skipScrolling
        if (mEmulator == null) return
        val rowsInHistory = mEmulator!!.screen.activeTranscriptRows
        if (topRow < -rowsInHistory) topRow = -rowsInHistory
        if (isSelectingText || mEmulator!!.isAutoScrollDisabled) {

            // Do not scroll when selecting text.
            val rowShift = mEmulator!!.scrollCounter
            if (-topRow + rowShift > rowsInHistory) {
                // .. unless we're hitting the end of history transcript, in which
                // case we abort text selection and scroll to end.
                if (isSelectingText) stopTextSelectionMode()
                if (mEmulator!!.isAutoScrollDisabled) {
                    topRow = -rowsInHistory
                    skipScr = true
                }
            } else {
                skipScr = true
                topRow -= rowShift
                decrementYTextSelectionCursors(rowShift)
            }
        }
        if (!skipScr && topRow != 0) {
            // Scroll down if not already there.
            if (topRow < -3) {
                // Awaken scroll bars only if scrolling a noticeable amount
                // - we do not want visible scroll bars during normal typing
                // of one row at a time.
                awakenScrollBars()
            }
            topRow = 0
        }
        mEmulator!!.clearScrollCounter()
        invalidate()
        if (mAccessibilityEnabled) contentDescription = text
    }

    /** This must be called by the hosting activity in [android.app.Activity.onContextMenuClosed]
     * when context menu for the [TerminalView] is started by
     * [TextSelectionCursorController.ACTION_MORE] is closed.  */
    fun onContextMenuClosed(menu: Menu?) {
        // Unset the stored text since it shouldn't be used anymore and should be cleared from memory
        unsetStoredSelectedText()
    }

    /**
     * Sets the text size, which in turn sets the number of rows and columns.
     *
     * @param textSize the new font size, in density-independent pixels.
     */
    fun setTextSize(textSize: Int) {
        mRenderer = TerminalRenderer(textSize, if (mRenderer == null) Typeface.MONOSPACE else mRenderer!!.mTypeface)
        updateSize()
    }

    fun setTypeface(newTypeface: Typeface?) {
        mRenderer = TerminalRenderer(mRenderer!!.mTextSize, newTypeface)
        updateSize()
        invalidate()
    }

    override fun onCheckIsTextEditor(): Boolean {
        return true
    }

    override fun isOpaque(): Boolean {
        return true
    }

    /**
     * Get the zero indexed column and row of the terminal view for the
     * position of the event.
     *
     * @param event The event with the position to get the column and row for.
     * @param relativeToScroll If true the column number will take the scroll
     * position into account. E.g. if scrolled 3 lines up and the event
     * position is in the top left, column will be -3 if relativeToScroll is
     * true and 0 if relativeToScroll is false.
     * @return Array with the column and row.
     */
    fun getColumnAndRow(event: MotionEvent?, relativeToScroll: Boolean): IntArray {
        val column = (event!!.x / mRenderer!!.fontWidth).toInt()
        var row = ((event.y - mRenderer!!.mFontLineSpacingAndAscent) / mRenderer!!.fontLineSpacing).toInt()
        if (relativeToScroll) {
            row += topRow
        }
        return intArrayOf(column, row)
    }

    /** Send a single mouse event code to the terminal.  */
    fun sendMouseEventCode(e: MotionEvent?, button: Int, pressed: Boolean) {
        val columnAndRow = getColumnAndRow(e, false)
        var x = columnAndRow[0] + 1
        var y = columnAndRow[1] + 1
        if (pressed && (button == TerminalEmulator.MOUSE_WHEELDOWN_BUTTON || button == TerminalEmulator.MOUSE_WHEELUP_BUTTON)) {
            if (mMouseStartDownTime == e!!.downTime) {
                x = mMouseScrollStartX
                y = mMouseScrollStartY
            } else {
                mMouseStartDownTime = e.downTime
                mMouseScrollStartX = x
                mMouseScrollStartY = y
            }
        }
        mEmulator!!.sendMouseEvent(button, x, y, pressed)
    }

    /** Perform a scroll, either from dragging the screen or by scrolling a mouse wheel.  */
    fun doScroll(event: MotionEvent?, rowsDown: Int) {
        val up = rowsDown < 0
        val amount = abs(rowsDown)
        for (i in 0 until amount) {
            if (mEmulator!!.isMouseTrackingActive) {
                sendMouseEventCode(
                    event,
                    if (up) TerminalEmulator.MOUSE_WHEELUP_BUTTON else TerminalEmulator.MOUSE_WHEELDOWN_BUTTON,
                    true
                )
            } else if (mEmulator!!.isAlternateBufferActive) {
                // Send up and down key events for scrolling, which is what some terminals do to make scroll work in
                // e.g. less, which shifts to the alt screen without mouse handling.
                handleKeyCode(if (up) KeyEvent.KEYCODE_DPAD_UP else KeyEvent.KEYCODE_DPAD_DOWN, 0)
            } else {
                val newTopRow = 0.coerceAtMost((-mEmulator!!.screen.activeTranscriptRows).coerceAtLeast(topRow + if (up) -1 else 1))
                val offset = newTopRow - topRow
                topRow = newTopRow

                if (!awakenScrollBars()) invalidate()
                mClient!!.onScroll(offset)
            }
        }
    }

    /** Overriding [View.onGenericMotionEvent].  */
    override fun onGenericMotionEvent(event: MotionEvent): Boolean {
        if (mEmulator != null && event.isFromSource(InputDevice.SOURCE_MOUSE) && event.action == MotionEvent.ACTION_SCROLL) {
            // Handle mouse wheel scrolling.
            val up = event.getAxisValue(MotionEvent.AXIS_VSCROLL) > 0.0f
            doScroll(event, if (up) -3 else 3)
            return true
        }
        return false
    }

    @SuppressLint("ClickableViewAccessibility")
    override fun onTouchEvent(event: MotionEvent): Boolean {
        if (mEmulator == null) return true
        val action = event.action
        if (isSelectingText) {
            updateFloatingToolbarVisibility(event)
            mGestureRecognizer.onTouchEvent(event)
            return true
        } else if (event.isFromSource(InputDevice.SOURCE_MOUSE)) {
            if (event.isButtonPressed(MotionEvent.BUTTON_SECONDARY)) {
                if (action == MotionEvent.ACTION_DOWN) showContextMenu()
                return true
            } else if (event.isButtonPressed(MotionEvent.BUTTON_TERTIARY)) {
                val clipboardManager = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                val clipData = clipboardManager.primaryClip
                if (clipData != null) {
                    val clipItem = clipData.getItemAt(0)
                    if (clipItem != null) {
                        val text = clipItem.coerceToText(context)
                        if (!TextUtils.isEmpty(text)) mEmulator!!.paste(text.toString())
                    }
                }
            } else if (mEmulator!!.isMouseTrackingActive) { // BUTTON_PRIMARY.
                when (event.action) {
                    MotionEvent.ACTION_DOWN, MotionEvent.ACTION_UP -> sendMouseEventCode(
                        event, TerminalEmulator.MOUSE_LEFT_BUTTON, event.action == MotionEvent.ACTION_DOWN
                    )
                    MotionEvent.ACTION_MOVE -> sendMouseEventCode(event, TerminalEmulator.MOUSE_LEFT_BUTTON_MOVED, true)
                }
            }
        }
        mGestureRecognizer.onTouchEvent(event)
        return true
    }

    override fun onKeyPreIme(keyCode: Int, event: KeyEvent): Boolean {
        if (TERMINAL_VIEW_KEY_LOGGING_ENABLED) mClient!!.logInfo(LOG_TAG, "onKeyPreIme(keyCode=$keyCode, event=$event)")
        if (keyCode == KeyEvent.KEYCODE_BACK) {
            if (isSelectingText) {
                stopTextSelectionMode()
                return true
            } else if (mClient!!.shouldBackButtonBeMappedToEscape) {
                // Intercept back button to treat it as escape:
                when (event.action) {
                    KeyEvent.ACTION_DOWN -> return onKeyDown(keyCode, event)
                    KeyEvent.ACTION_UP -> return onKeyUp(keyCode, event)
                }
            }
        } else if (mClient!!.shouldUseCtrlSpaceWorkaround && keyCode == KeyEvent.KEYCODE_SPACE && event.isCtrlPressed) {
            /* ctrl+space does not work on some ROMs without this workaround.
               However, this breaks it on devices where it works out of the box. */
            return onKeyDown(keyCode, event)
        }
        return super.onKeyPreIme(keyCode, event)
    }

    /**
     * Key presses in software keyboards will generally NOT trigger this listener, although some
     * may elect to do so in some situations. Do not rely on this to catch software key presses.
     * Gboard calls this when shouldEnforceCharBasedInput() is disabled (InputType.TYPE_NULL) instead
     * of calling commitText(), with deviceId=-1. However, Hacker's Keyboard, OpenBoard, LG Keyboard
     * call commitText().
     *
     * This function may also be called directly without android calling it, like by
     * `TerminalExtraKeys` which generates a KeyEvent manually which uses [KeyCharacterMap.VIRTUAL_KEYBOARD]
     * as the device (deviceId=-1), as does Gboard. That would normally use mappings defined in
     * `/system/usr/keychars/Virtual.kcm`. You can run `dumpsys input` to find the `KeyCharacterMapFile`
     * used by virtual keyboard or hardware keyboard. Note that virtual keyboard device is not the
     * same as software keyboard, like Gboard, etc. Its a fake device used for generating events and
     * for testing.
     *
     * We handle shift key in `commitText()` to convert codepoint to uppercase case there with a
     * call to [Character.toUpperCase], but here we instead rely on getUnicodeChar() for
     * conversion of keyCode, for both hardware keyboard shift key (via effectiveMetaState) and
     * `mClient.readShiftKey()`, based on value in kcm files.
     * This may result in different behaviour depending on keyboard and android kcm files set for the
     * InputDevice for the event passed to this function. This will likely be an issue for non-english
     * languages since `Virtual.kcm` in english only by default or at least in AOSP. For both hardware
     * shift key (via effectiveMetaState) and `mClient.readShiftKey()`, `getUnicodeChar()` is used
     * for shift specific behaviour which usually is to uppercase.
     *
     * For fn key on hardware keyboard, android checks kcm files for hardware keyboards, which is
     * `Generic.kcm` by default, unless a vendor specific one is defined. The event passed will have
     * [KeyEvent.META_FUNCTION_ON] set. If the kcm file only defines a single character or unicode
     * code point `\\uxxxx`, then only one event is passed with that value. However, if kcm defines
     * a `fallback` key for fn or others, like `key DPAD_UP { ... fn: fallback PAGE_UP }`, then
     * android will first pass an event with original key `DPAD_UP` and [KeyEvent.META_FUNCTION_ON]
     * set. But this function will not consume it and android will pass another event with `PAGE_UP`
     * and [KeyEvent.META_FUNCTION_ON] not set, which will be consumed.
     *
     * Now there are some other issues as well, firstly ctrl and alt flags are not passed to
     * `getUnicodeChar()`, so modified key values in kcm are not used. Secondly, if the kcm file
     * for other modifiers like shift or fn define a non-alphabet, like { fn: '\u0015' } to act as
     * DPAD_LEFT, the `getUnicodeChar()` will correctly return `21` as the code point but action will
     * not happen because the `handleKeyCode()` function that transforms DPAD_LEFT to `\033[D`
     * escape sequence for the terminal to perform the left action would not be called since its
     * called before `getUnicodeChar()` and terminal will instead get `21 0x15 Negative Acknowledgement`.
     * The solution to such issues is calling `getUnicodeChar()` before the call to `handleKeyCode()`
     * if user has defined a custom kcm file, like done in POC mentioned in #2237. Note that
     * Hacker's Keyboard calls `commitText()` so don't test fn/shift with it for this function.
     * https://github.com/termux/termux-app/pull/2237
     * https://github.com/agnostic-apollo/termux-app/blob/terminal-code-point-custom-mapping/terminal-view/src/main/java/com/termux/view/TerminalView.java
     *
     * Key Character Map (kcm) and Key Layout (kl) files info:
     * https://source.android.com/devices/input/key-character-map-files
     * https://source.android.com/devices/input/key-layout-files
     * https://source.android.com/devices/input/keyboard-devices
     * AOSP kcm and kl files:
     * https://cs.android.com/android/platform/superproject/+/android-11.0.0_r40:frameworks/base/data/keyboards
     * https://cs.android.com/android/platform/superproject/+/android-11.0.0_r40:frameworks/base/packages/InputDevices/res/raw
     *
     * KeyCodes:
     * https://cs.android.com/android/platform/superproject/+/android-11.0.0_r40:frameworks/base/core/java/android/view/KeyEvent.java
     * https://cs.android.com/android/platform/superproject/+/master:frameworks/native/include/android/keycodes.h
     *
     * `dumpsys input`:
     * https://cs.android.com/android/platform/superproject/+/android-11.0.0_r40:frameworks/native/services/inputflinger/reader/EventHub.cpp;l=1917
     *
     * Loading of keymap:
     * https://cs.android.com/android/platform/superproject/+/android-11.0.0_r40:frameworks/native/services/inputflinger/reader/EventHub.cpp;l=1644
     * https://cs.android.com/android/platform/superproject/+/android-11.0.0_r40:frameworks/native/libs/input/Keyboard.cpp;l=41
     * https://cs.android.com/android/platform/superproject/+/android-11.0.0_r40:frameworks/native/libs/input/InputDevice.cpp
     * OVERLAY keymaps for hardware keyboards may be combined as well:
     * https://cs.android.com/android/platform/superproject/+/android-11.0.0_r40:frameworks/native/libs/input/KeyCharacterMap.cpp;l=165
     * https://cs.android.com/android/platform/superproject/+/android-11.0.0_r40:frameworks/native/libs/input/KeyCharacterMap.cpp;l=831
     *
     * Parse kcm file:
     * https://cs.android.com/android/platform/superproject/+/android-11.0.0_r40:frameworks/native/libs/input/KeyCharacterMap.cpp;l=727
     * Parse key value:
     * https://cs.android.com/android/platform/superproject/+/android-11.0.0_r40:frameworks/native/libs/input/KeyCharacterMap.cpp;l=981
     *
     * `KeyEvent.getUnicodeChar()`
     * https://cs.android.com/android/platform/superproject/+/android-11.0.0_r40:frameworks/base/core/java/android/view/KeyEvent.java;l=2716
     * https://cs.android.com/android/platform/superproject/+/master:frameworks/base/core/java/android/view/KeyCharacterMap.java;l=368
     * https://cs.android.com/android/platform/superproject/+/android-11.0.0_r40:frameworks/base/core/jni/android_view_KeyCharacterMap.cpp;l=117
     * https://cs.android.com/android/platform/superproject/+/android-11.0.0_r40:frameworks/native/libs/input/KeyCharacterMap.cpp;l=231
     *
     * Keyboard layouts advertised by applications, like for hardware keyboards via #ACTION_QUERY_KEYBOARD_LAYOUTS
     * Config is stored in `/data/system/input-manager-state.xml`
     * https://github.com/ris58h/custom-keyboard-layout
     * Loading from apps:
     * https://cs.android.com/android/platform/superproject/+/master:frameworks/base/services/core/java/com/android/server/input/InputManagerService.java;l=1221
     * Set:
     * https://cs.android.com/android/platform/superproject/+/android-11.0.0_r40:frameworks/base/core/java/android/hardware/input/InputManager.java;l=89
     * https://cs.android.com/android/platform/superproject/+/android-11.0.0_r40:frameworks/base/core/java/android/hardware/input/InputManager.java;l=543
     * https://cs.android.com/android/platform/superproject/+/android-11.0.0_r40:packages/apps/Settings/src/com/android/settings/inputmethod/KeyboardLayoutDialogFragment.java;l=167
     * https://cs.android.com/android/platform/superproject/+/master:frameworks/base/services/core/java/com/android/server/input/InputManagerService.java;l=1385
     * https://cs.android.com/android/platform/superproject/+/master:frameworks/base/services/core/java/com/android/server/input/PersistentDataStore.java
     * Get overlay keyboard layout
     * https://cs.android.com/android/platform/superproject/+/master:frameworks/base/services/core/java/com/android/server/input/InputManagerService.java;l=2158
     * https://cs.android.com/android/platform/superproject/+/android-11.0.0_r40:frameworks/base/services/core/jni/com_android_server_input_InputManagerService.cpp;l=616
     */
    override fun onKeyDown(keyCode: Int, event: KeyEvent): Boolean {
        if (TERMINAL_VIEW_KEY_LOGGING_ENABLED) mClient!!.logInfo(
            LOG_TAG, "onKeyDown(keyCode=" + keyCode + ", isSystem()=" + event.isSystem + ", event=" + event + ")"
        )
        if (mEmulator == null) return true
        if (isSelectingText) {
            stopTextSelectionMode()
        }
        if (mClient!!.onKeyDown(keyCode, event, currentSession)) {
            invalidate()
            return true
        } else if (event.isSystem && (!mClient!!.shouldBackButtonBeMappedToEscape || keyCode != KeyEvent.KEYCODE_BACK)) {
            return super.onKeyDown(keyCode, event)
        } else if (event.action == KeyEvent.ACTION_MULTIPLE && keyCode == KeyEvent.KEYCODE_UNKNOWN) {
            currentSession!!.write(event.characters)
            return true
        }
        val metaState = event.metaState
        val controlDown = event.isCtrlPressed || mClient!!.readControlKey()
        val leftAltDown = metaState and KeyEvent.META_ALT_LEFT_ON != 0 || mClient!!.readAltKey()
        val shiftDown = event.isShiftPressed || mClient!!.readShiftKey()
        val rightAltDownFromEvent = metaState and KeyEvent.META_ALT_RIGHT_ON != 0
        var keyMod = 0
        if (controlDown) keyMod = keyMod or KeyHandler.KEYMOD_CTRL
        if (event.isAltPressed || leftAltDown) keyMod = keyMod or KeyHandler.KEYMOD_ALT
        if (shiftDown) keyMod = keyMod or KeyHandler.KEYMOD_SHIFT
        if (event.isNumLockOn) keyMod = keyMod or KeyHandler.KEYMOD_NUM_LOCK
        // https://github.com/termux/termux-app/issues/731
        if (!event.isFunctionPressed && handleKeyCode(keyCode, keyMod)) {
            if (TERMINAL_VIEW_KEY_LOGGING_ENABLED) mClient!!.logInfo(LOG_TAG, "handleKeyCode() took key event")
            return true
        }

        // Clear Ctrl since we handle that ourselves:
        var bitsToClear = KeyEvent.META_CTRL_MASK
        if (rightAltDownFromEvent) {
            // Let right Alt/Alt Gr be used to compose characters.
        } else {
            // Use left alt to send to terminal (e.g. Left Alt+B to jump back a word), so remove:
            bitsToClear = bitsToClear or (KeyEvent.META_ALT_ON or KeyEvent.META_ALT_LEFT_ON)
        }
        var effectiveMetaState = event.metaState and bitsToClear.inv()
        if (shiftDown) effectiveMetaState = effectiveMetaState or (KeyEvent.META_SHIFT_ON or KeyEvent.META_SHIFT_LEFT_ON)
        if (mClient!!.readFnKey()) effectiveMetaState = effectiveMetaState or KeyEvent.META_FUNCTION_ON
        var result = event.getUnicodeChar(effectiveMetaState)
        if (TERMINAL_VIEW_KEY_LOGGING_ENABLED) mClient!!.logInfo(
            LOG_TAG, "KeyEvent#getUnicodeChar($effectiveMetaState) returned: $result"
        )
        if (result == 0) {
            return false
        }
        val oldCombiningAccent = mCombiningAccent
        if (result and KeyCharacterMap.COMBINING_ACCENT != 0) {
            // If entered combining accent previously, write it out:
            if (mCombiningAccent != 0) inputCodePoint(event.deviceId, mCombiningAccent, controlDown, leftAltDown)
            mCombiningAccent = result and KeyCharacterMap.COMBINING_ACCENT_MASK
        } else {
            if (mCombiningAccent != 0) {
                val combinedChar = KeyCharacterMap.getDeadChar(mCombiningAccent, result)
                if (combinedChar > 0) result = combinedChar
                mCombiningAccent = 0
            }
            inputCodePoint(event.deviceId, result, controlDown, leftAltDown)
        }
        if (mCombiningAccent != oldCombiningAccent) invalidate()
        return true
    }

    fun inputCodePoint(eventSource: Int, codePoint: Int, controlDownFromEvent: Boolean, leftAltDownFromEvent: Boolean) {
        if (TERMINAL_VIEW_KEY_LOGGING_ENABLED) {
            mClient!!.logInfo(
                LOG_TAG,
                "inputCodePoint(eventSource=$eventSource, codePoint=$codePoint, controlDownFromEvent=$controlDownFromEvent, leftAltDownFromEvent=$leftAltDownFromEvent)"
            )
        }
        if (currentSession == null) return

        // Ensure cursor is shown when a key is pressed down like long hold on (arrow) keys
        if (mEmulator != null) mEmulator!!.setCursorBlinkState(true)
        val controlDown = controlDownFromEvent || mClient!!.readControlKey()
        val altDown = leftAltDownFromEvent || mClient!!.readAltKey()
        if (mClient!!.onCodePoint(codePoint, controlDown, currentSession)) return
        var cp = codePoint
        if (controlDown) {
            when (codePoint) {
                in 'a'.code..'z'.code -> {
                    cp = codePoint - 'a'.code + 1
                }
                in 'A'.code..'Z'.code -> {
                    cp = codePoint - 'A'.code + 1
                }
                ' '.code, '2'.code -> {
                    cp = 0
                }
                '['.code, '3'.code -> {
                    cp = 27 // ^[ (Esc)
                }
                '\\'.code, '4'.code -> {
                    cp = 28
                }
                ']'.code, '5'.code -> {
                    cp = 29
                }
                '^'.code, '6'.code -> {
                    cp = 30 // control-^
                }
                '_'.code, '7'.code, '/'.code -> {
                    // "Ctrl-/ sends 0x1f which is equivalent of Ctrl-_ since the days of VT102"
                    // - http://apple.stackexchange.com/questions/24261/how-do-i-send-c-that-is-control-slash-to-the-terminal
                    cp = 31
                }
                '8'.code -> {
                    cp = 127 // DEL
                }
            }
        }
        if (cp > -1) {
            // If not virtual or soft keyboard.
            if (eventSource > KEY_EVENT_SOURCE_SOFT_KEYBOARD) {
                // Work around bluetooth keyboards sending funny unicode characters instead
                // of the more normal ones from ASCII that terminal programs expect - the
                // desire to input the original characters should be low.
                when (cp) {
                    0x02DC -> cp = 0x007E // TILDE (~).
                    0x02CB -> cp = 0x0060 // GRAVE ACCENT (`).
                    0x02C6 -> cp = 0x005E // CIRCUMFLEX ACCENT (^).
                }
            }

            // If left alt, send escape before the code point to make e.g. Alt+B and Alt+F work in readline:
            currentSession!!.writeCodePoint(altDown, cp)
        }
    }

    /** Input the specified keyCode if applicable and return if the input was consumed.  */
    fun handleKeyCode(keyCode: Int, keyMod: Int): Boolean {
        // Ensure cursor is shown when a key is pressed down like long hold on (arrow) keys
        if (mEmulator != null) mEmulator!!.setCursorBlinkState(true)
        val term = currentSession!!.emulator
        val code = getCode(keyCode, keyMod, term!!.isCursorKeysApplicationMode, term.isKeypadApplicationMode)
            ?: return false
        currentSession!!.write(code)
        return true
    }

    /**
     * Called when a key is released in the view.
     *
     * @param keyCode The keycode of the key which was released.
     * @param event   A [KeyEvent] describing the event.
     * @return Whether the event was handled.
     */
    override fun onKeyUp(keyCode: Int, event: KeyEvent): Boolean {
        if (TERMINAL_VIEW_KEY_LOGGING_ENABLED) mClient!!.logInfo(LOG_TAG, "onKeyUp(keyCode=$keyCode, event=$event)")

        // Do not return for KEYCODE_BACK and send it to the client since user may be trying
        // to exit the activity.
        if (mEmulator == null && keyCode != KeyEvent.KEYCODE_BACK) return true
        if (mClient!!.onKeyUp(keyCode, event)) {
            invalidate()
            return true
        } else if (event.isSystem) {
            // Let system key events through.
            return super.onKeyUp(keyCode, event)
        }
        return true
    }

    /**
     * This is called during layout when the size of this view has changed. If you were just added to the view
     * hierarchy, you're called with the old values of 0.
     */
    override fun onSizeChanged(w: Int, h: Int, oldw: Int, oldh: Int) {
        updateSize()
    }

    /** Check if the terminal size in rows and columns should be updated.  */
    fun updateSize() {
        val viewWidth = width
        val viewHeight = height
        if (viewWidth == 0 || viewHeight == 0 || currentSession == null) return

        // Set to 80 and 24 if you want to enable vttest.
        val newColumns = 4.coerceAtLeast((viewWidth / mRenderer!!.fontWidth).toInt())
        val newRows = 4.coerceAtLeast((viewHeight - mRenderer!!.mFontLineSpacingAndAscent) / mRenderer!!.fontLineSpacing)
        if (mEmulator == null || newColumns != mEmulator!!.mColumns || newRows != mEmulator!!.mRows) {
            currentSession!!.updateSize(newColumns, newRows)
            mEmulator = currentSession!!.emulator
            mClient!!.onEmulatorSet()

            // Update mTerminalCursorBlinkerRunnable inner class mEmulator on session change
            if (mTerminalCursorBlinkerRunnable != null) mTerminalCursorBlinkerRunnable!!.setEmulator(mEmulator)
            topRow = 0
            scrollTo(0, 0)
            invalidate()
        }
    }

    override fun onDraw(canvas: Canvas) {
        if (mEmulator == null) {
            canvas.drawColor(-0x1000000)
        } else {
            // render the terminal view and highlight any selected text
            val sel = mDefaultSelectors
            if (mTextSelectionCursorController != null) {
                mTextSelectionCursorController!!.getSelectors(sel)
            }
            mRenderer!!.render(mEmulator!!, canvas, topRow, sel[0], sel[1], sel[2], sel[3])

            // render the text selection handles
            renderTextSelection()
        }
    }

    private val text: CharSequence
        get() = mEmulator!!.screen.getSelectedText(0, topRow, mEmulator!!.mColumns, topRow + mEmulator!!.mRows)

    fun getCursorX(x: Float): Int {
        return (x / mRenderer!!.fontWidth).toInt()
    }

    fun getCursorY(y: Float): Int {
        return ((y - 40) / mRenderer!!.fontLineSpacing + topRow).toInt()
    }

    fun getPointX(cx: Int): Int {
        val x = if (cx > mEmulator!!.mColumns) mEmulator!!.mColumns else cx

        return (x * mRenderer!!.fontWidth).roundToInt()
    }

    fun getPointY(cy: Int): Int {
        return ((cy - topRow) * mRenderer!!.fontLineSpacing).toFloat().roundToInt()
    }

    /**
     * Define functions required for AutoFill API
     */
    @RequiresApi(api = Build.VERSION_CODES.O)
    override fun autofill(value: AutofillValue) {
        if (value.isText) {
            currentSession!!.write(value.textValue.toString())
        }
    }

    @RequiresApi(api = Build.VERSION_CODES.O)
    override fun getAutofillType(): Int {
        return AUTOFILL_TYPE_TEXT
    }

    @RequiresApi(api = Build.VERSION_CODES.O)
    override fun getAutofillValue(): AutofillValue? {
        return AutofillValue.forText("")
    }

    /**
     * Set terminal cursor blinker rate. It must be between [.TERMINAL_CURSOR_BLINK_RATE_MIN]
     * and [.TERMINAL_CURSOR_BLINK_RATE_MAX], otherwise it will be disabled.
     *
     * The [.setTerminalCursorBlinkerState] must be called after this
     * for changes to take effect if not disabling.
     *
     * @param blinkRate The value to set.
     * @return Returns `true` if setting blinker rate was successfully set, otherwise [@code false}.
     */
    @Synchronized
    fun setTerminalCursorBlinkerRate(blinkRate: Int): Boolean {
        val result: Boolean

        // If cursor blinking rate is not valid
        if (blinkRate != 0 && (blinkRate < TERMINAL_CURSOR_BLINK_RATE_MIN || blinkRate > TERMINAL_CURSOR_BLINK_RATE_MAX)) {
            mClient!!.logError(
                LOG_TAG,
                "The cursor blink rate must be in between $TERMINAL_CURSOR_BLINK_RATE_MIN-$TERMINAL_CURSOR_BLINK_RATE_MAX: $blinkRate"
            )
            mTerminalCursorBlinkerRate = 0
            result = false
        } else {
            mClient!!.logVerbose(LOG_TAG, "Setting cursor blinker rate to $blinkRate")
            mTerminalCursorBlinkerRate = blinkRate
            result = true
        }
        if (mTerminalCursorBlinkerRate == 0) {
            mClient!!.logVerbose(LOG_TAG, "Cursor blinker disabled")
            stopTerminalCursorBlinker()
        }
        return result
    }

    /**
     * Sets whether cursor blinker should be started or stopped. Cursor blinker will only be
     * started if [.mTerminalCursorBlinkerRate] does not equal 0 and is between
     * [.TERMINAL_CURSOR_BLINK_RATE_MIN] and [.TERMINAL_CURSOR_BLINK_RATE_MAX].
     *
     * This should be called when the view holding this activity is resumed or stopped so that
     * cursor blinker does not run when activity is not visible. If you call this on onResume()
     * to start cursor blinking, then ensure that [.mEmulator] is set, otherwise wait for the
     * [TerminalViewClient.onEmulatorSet] event after calling [.attachSession]
     * for the first session added in the activity since blinking will not start if [.mEmulator]
     * is not set, like if activity is started again after exiting it with double back press. Do not
     * call this directly after [.attachSession] since [.updateSize]
     * may return without setting [.mEmulator] since width/height may be 0. Its called again in
     * [.onSizeChanged]. Calling on onResume() if emulator is already set
     * is necessary, since onEmulatorSet() may not be called after activity is started after device
     * display timeout with double tap and not power button.
     *
     * It should also be called on the
     * [com.termux.terminal.TerminalSessionClient.onTerminalCursorStateChange]
     * callback when cursor is enabled or disabled so that blinker is disabled if cursor is not
     * to be shown. It should also be checked if activity is visible if blinker is to be started
     * before calling this.
     *
     * It should also be called after terminal is reset with [TerminalSession.reset] in case
     * cursor blinker was disabled before reset due to call to
     * [com.termux.terminal.TerminalSessionClient.onTerminalCursorStateChange].
     *
     * How cursor blinker starting works is by registering a [Runnable] with the looper of
     * the main thread of the app which when run, toggles the cursor blinking state and re-registers
     * itself to be called with the delay set by [.mTerminalCursorBlinkerRate]. When cursor
     * blinking needs to be disabled, we just cancel any callbacks registered. We don't run our own
     * "thread" and let the thread for the main looper do the work for us, whose usage is also
     * required to update the UI, since it also handles other calls to update the UI as well based
     * on a queue.
     *
     * Note that when moving cursor in text editors like nano, the cursor state is quickly
     * toggled `-> off -> on`, which would call this very quickly sequentially. So that if cursor
     * is moved 2 or more times quickly, like long hold on arrow keys, it would trigger
     * `-> off -> on -> off -> on -> ...`, and the "on" callback at index 2 is automatically
     * cancelled by next "off" callback at index 3 before getting a chance to be run. For this case
     * we log only if [.TERMINAL_VIEW_KEY_LOGGING_ENABLED] is enabled, otherwise would clutter
     * the log. We don't start the blinking with a delay to immediately show cursor in case it was
     * previously not visible.
     *
     * @param start If cursor blinker should be started or stopped.
     * @param startOnlyIfCursorEnabled If set to `true`, then it will also be checked if the
     * cursor is even enabled by [TerminalEmulator] before
     * starting the cursor blinker.
     */
    @Synchronized
    fun setTerminalCursorBlinkerState(start: Boolean, startOnlyIfCursorEnabled: Boolean) {
        // Stop any existing cursor blinker callbacks
        stopTerminalCursorBlinker()
        if (mEmulator == null) return
        mEmulator!!.setCursorBlinkingEnabled(false)
        if (start) {
            // If cursor blinker is not enabled or is not valid
            if (mTerminalCursorBlinkerRate < TERMINAL_CURSOR_BLINK_RATE_MIN || mTerminalCursorBlinkerRate > TERMINAL_CURSOR_BLINK_RATE_MAX) return else if (startOnlyIfCursorEnabled && !mEmulator!!.isCursorEnabled) {
                if (TERMINAL_VIEW_KEY_LOGGING_ENABLED) mClient!!.logVerbose(
                    LOG_TAG, "Ignoring call to start cursor blinker since cursor is not enabled"
                )
                return
            }

            // Start cursor blinker runnable
            if (TERMINAL_VIEW_KEY_LOGGING_ENABLED) mClient!!.logVerbose(
                LOG_TAG, "Starting cursor blinker with the blink rate $mTerminalCursorBlinkerRate"
            )
            if (mTerminalCursorBlinkerHandler == null) mTerminalCursorBlinkerHandler = Handler(Looper.getMainLooper())
            mTerminalCursorBlinkerRunnable = TerminalCursorBlinkerRunnable(mEmulator, mTerminalCursorBlinkerRate)
            mEmulator!!.setCursorBlinkingEnabled(true)
            mTerminalCursorBlinkerRunnable!!.run()
        }
    }

    /**
     * Cancel the terminal cursor blinker callbacks
     */
    private fun stopTerminalCursorBlinker() {
        if (mTerminalCursorBlinkerHandler != null && mTerminalCursorBlinkerRunnable != null) {
            if (TERMINAL_VIEW_KEY_LOGGING_ENABLED) mClient!!.logVerbose(LOG_TAG, "Stopping cursor blinker")
            mTerminalCursorBlinkerHandler!!.removeCallbacks(mTerminalCursorBlinkerRunnable!!)
        }
    }

    private inner class TerminalCursorBlinkerRunnable(
        private var mEmulator: TerminalEmulator?, private val mBlinkRate: Int
    ) : Runnable {
        // Initialize with false so that initial blink state is visible after toggling
        var mCursorVisible = false
        fun setEmulator(emulator: TerminalEmulator?) {
            mEmulator = emulator
        }

        override fun run() {
            try {
                if (mEmulator != null) {
                    // Toggle the blink state and then invalidate() the view so
                    // that onDraw() is called, which then calls TerminalRenderer.render()
                    // which checks with TerminalEmulator.shouldCursorBeVisible() to decide whether
                    // to draw the cursor or not
                    mCursorVisible = !mCursorVisible
                    //mClient.logVerbose(LOG_TAG, "Toggling cursor blink state to " + mCursorVisible);
                    mEmulator!!.setCursorBlinkState(mCursorVisible)
                    invalidate()
                }
            } finally {
                // Recall the Runnable after mBlinkRate milliseconds to toggle the blink state
                mTerminalCursorBlinkerHandler!!.postDelayed(this, mBlinkRate.toLong())
            }
        }
    }

    /**
     * Define functions required for text selection and its handles.
     */
    val textSelectionCursorController: TextSelectionCursorController
        get() {
            if (mTextSelectionCursorController == null) {
                mTextSelectionCursorController = TextSelectionCursorController(this)
                val observer = viewTreeObserver
                observer?.addOnTouchModeChangeListener(mTextSelectionCursorController)
            }
            return mTextSelectionCursorController!!
        }

    private fun showTextSelectionCursors(event: MotionEvent?) {
        textSelectionCursorController.show(event)
    }

    private fun hideTextSelectionCursors(): Boolean {
        return textSelectionCursorController.hide()
    }

    private fun renderTextSelection() {
        if (mTextSelectionCursorController != null) mTextSelectionCursorController!!.render()
    }

    val isSelectingText: Boolean
        get() = if (mTextSelectionCursorController != null) {
            mTextSelectionCursorController!!.isActive
        } else {
            false
        }

    /** Get the currently selected text if selecting.  */
    val selectedText: String?
        get() = if (isSelectingText && mTextSelectionCursorController != null) mTextSelectionCursorController!!.selectedText else null

    /** Get the selected text stored before "MORE" button was pressed on the context menu.  */
    val storedSelectedText: String?
        get() = mTextSelectionCursorController?.storedSelectedText

    /** Unset the selected text stored before "MORE" button was pressed on the context menu.  */
    fun unsetStoredSelectedText() {
        if (mTextSelectionCursorController != null) mTextSelectionCursorController!!.unsetStoredSelectedText()
    }

    private val textSelectionActionMode: ActionMode?
        get() = mTextSelectionCursorController?.actionMode

    fun startTextSelectionMode(event: MotionEvent?) {
        if (!requestFocus()) {
            return
        }
        showTextSelectionCursors(event)
        mClient!!.copyModeChanged(isSelectingText)
        invalidate()
    }

    fun stopTextSelectionMode() {
        if (hideTextSelectionCursors()) {
            mClient!!.copyModeChanged(isSelectingText)
            invalidate()
        }
    }

    private fun decrementYTextSelectionCursors(decrement: Int) {
        if (mTextSelectionCursorController != null) {
            mTextSelectionCursorController!!.decrementYTextSelectionCursors(decrement)
        }
    }

    override fun onAttachedToWindow() {
        super.onAttachedToWindow()
        if (mTextSelectionCursorController != null) {
            viewTreeObserver.addOnTouchModeChangeListener(mTextSelectionCursorController)
        }
    }

    override fun onDetachedFromWindow() {
        super.onDetachedFromWindow()
        if (mTextSelectionCursorController != null) {
            // Might solve the following exception
            // android.view.WindowLeaked: Activity com.termux.app.TermuxActivity has leaked window android.widget.PopupWindow
            stopTextSelectionMode()
            viewTreeObserver.removeOnTouchModeChangeListener(mTextSelectionCursorController)
            mTextSelectionCursorController!!.onDetached()
        }
    }

    /**
     * Define functions required for long hold toolbar.
     */
    private val mShowFloatingToolbar: Runnable = Runnable {
        if (textSelectionActionMode != null) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                textSelectionActionMode!!.hide(0)
            } else {
                textSelectionActionMode!!.finish()
            }
        }
    }

    init { // NO_UCD (unused code)
        mGestureRecognizer = GestureAndScaleRecognizer(context, object : GestureAndScaleRecognizer.Listener {
            var scrolledWithFinger = false
            override fun onUp(e: MotionEvent?): Boolean {
                mScrollRemainder = 0.0f
                if (mEmulator != null && mEmulator!!.isMouseTrackingActive && !e!!.isFromSource(InputDevice.SOURCE_MOUSE) && !isSelectingText && !scrolledWithFinger) {
                    // Quick event processing when mouse tracking is active - do not wait for check of double tapping
                    // for zooming.
                    sendMouseEventCode(e, TerminalEmulator.MOUSE_LEFT_BUTTON, true)
                    sendMouseEventCode(e, TerminalEmulator.MOUSE_LEFT_BUTTON, false)
                    return true
                }
                scrolledWithFinger = false
                return false
            }

            override fun onSingleTapUp(e: MotionEvent?): Boolean {
                if (mEmulator == null) return true
                if (isSelectingText) {
                    stopTextSelectionMode()
                    return true
                }
                requestFocus()
                mClient!!.onSingleTapUp(e)
                return true
            }

            override fun onScroll(e2: MotionEvent?, dx: Float, dy: Float): Boolean {
                var distanceY = dy
                if (mEmulator == null) return true
                if (mEmulator!!.isMouseTrackingActive && e2!!.isFromSource(InputDevice.SOURCE_MOUSE)) {
                    // If moving with mouse pointer while pressing button, report that instead of scroll.
                    // This means that we never report moving with button press-events for touch input,
                    // since we cannot just start sending these events without a starting press event,
                    // which we do not do for touch input, only mouse in onTouchEvent().
                    sendMouseEventCode(e2, TerminalEmulator.MOUSE_LEFT_BUTTON_MOVED, true)
                } else {
                    scrolledWithFinger = true
                    distanceY += mScrollRemainder
                    val deltaRows = (distanceY / mRenderer!!.fontLineSpacing).toInt()
                    mScrollRemainder = distanceY - deltaRows * mRenderer!!.fontLineSpacing
                    doScroll(e2, deltaRows)
                }
                return true
            }

            override fun onScale(focusX: Float, focusY: Float, scale: Float): Boolean {
                if (mEmulator == null || isSelectingText) return true
                mScaleFactor *= scale
                mScaleFactor = mClient!!.onScale(mScaleFactor)
                return true
            }

            override fun onFling(e: MotionEvent?, velocityX: Float, velocityY: Float): Boolean {
                if (mEmulator == null) return true
                // Do not start scrolling until last fling has been taken care of:
                if (!mScroller.isFinished) return true
                val mouseTrackingAtStartOfFling = mEmulator!!.isMouseTrackingActive
                val scale = 0.25f
                if (mouseTrackingAtStartOfFling) {
                    mScroller.fling(
                        0, 0, 0, -(velocityY * scale).toInt(), 0, 0, -mEmulator!!.mRows / 2, mEmulator!!.mRows / 2
                    )
                } else {
                    mScroller.fling(
                        0, topRow, 0, -(velocityY * scale).toInt(), 0, 0, -mEmulator!!.screen.activeTranscriptRows, 0
                    )
                }
                post(object : Runnable {
                    private var mLastY = 0
                    override fun run() {
                        if (mouseTrackingAtStartOfFling != mEmulator!!.isMouseTrackingActive) {
                            mScroller.abortAnimation()
                            return
                        }
                        if (mScroller.isFinished) return
                        val more = mScroller.computeScrollOffset()
                        val newY = mScroller.currY
                        val diff = if (mouseTrackingAtStartOfFling) newY - mLastY else newY - topRow
                        doScroll(e, diff)
                        mLastY = newY
                        if (more) post(this)
                    }
                })
                return true
            }

            override fun onDown(x: Float, y: Float): Boolean {
                // Why is true not returned here?
                // https://developer.android.com/training/gestures/detector.html#detect-a-subset-of-supported-gestures
                // Although setting this to true still does not solve the following errors when long pressing in terminal view text area
                // ViewDragHelper: Ignoring pointerId=0 because ACTION_DOWN was not received for this pointer before ACTION_MOVE
                // Commenting out the call to mGestureDetector.onTouchEvent(event) in GestureAndScaleRecognizer#onTouchEvent() removes
                // the error logging, so issue is related to GestureDetector
                return false
            }

            override fun onDoubleTap(e: MotionEvent?): Boolean {
                // Do not treat is as a single confirmed tap - it may be followed by zoom.
                return false
            }

            override fun onLongPress(e: MotionEvent?) {
                if (mGestureRecognizer.isInProgress) return
                if (mClient!!.onLongPress(e)) return
                if (!isSelectingText) {
                    performHapticFeedback(HapticFeedbackConstants.LONG_PRESS)
                    startTextSelectionMode(e)
                }
            }
        })

        val am = context.getSystemService(Context.ACCESSIBILITY_SERVICE) as AccessibilityManager
        mAccessibilityEnabled = am.isEnabled
    }

    private fun showFloatingToolbar() {
        if (textSelectionActionMode != null) {
            val delay = ViewConfiguration.getDoubleTapTimeout()
            postDelayed(mShowFloatingToolbar, delay.toLong())
        }
    }

    fun hideFloatingToolbar() {
        if (textSelectionActionMode != null) {
            removeCallbacks(mShowFloatingToolbar)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                textSelectionActionMode!!.hide(-1)
            } else {
                textSelectionActionMode!!.finish();
            }
        }
    }

    fun updateFloatingToolbarVisibility(event: MotionEvent) {
        if (textSelectionActionMode != null) {
            when (event.actionMasked) {
                MotionEvent.ACTION_MOVE -> hideFloatingToolbar()
                MotionEvent.ACTION_UP, MotionEvent.ACTION_CANCEL -> showFloatingToolbar()
            }
        }
    }

    companion object {
        /** Log terminal view key and IME events.  */
        private var TERMINAL_VIEW_KEY_LOGGING_ENABLED = false
        const val TERMINAL_CURSOR_BLINK_RATE_MIN = 100
        const val TERMINAL_CURSOR_BLINK_RATE_MAX = 2000

        /** The [KeyEvent] is generated from a virtual keyboard, like manually with the [KeyEvent] constructor.  */
        const val KEY_EVENT_SOURCE_VIRTUAL_KEYBOARD = KeyCharacterMap.VIRTUAL_KEYBOARD // -1

        /** The [KeyEvent] is generated from a non-physical device, like if 0 value is returned by [KeyEvent.getDeviceId].  */
        const val KEY_EVENT_SOURCE_SOFT_KEYBOARD = 0
        private const val LOG_TAG = "TerminalView"
    }
}