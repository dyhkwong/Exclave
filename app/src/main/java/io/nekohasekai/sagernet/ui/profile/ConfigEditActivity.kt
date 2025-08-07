/******************************************************************************
 *                                                                            *
 * Copyright (C) 2021 by nekohasekai <contact-sagernet@sekai.icu>             *
 *                                                                            *
 * This program is free software: you can redistribute it and/or modify       *
 * it under the terms of the GNU General Public License as published by       *
 * the Free Software Foundation, either version 3 of the License, or          *
 *  (at your option) any later version.                                       *
 *                                                                            *
 * This program is distributed in the hope that it will be useful,            *
 * but WITHOUT ANY WARRANTY; without even the implied warranty of             *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the              *
 * GNU General Public License for more details.                               *
 *                                                                            *
 * You should have received a copy of the GNU General Public License          *
 * along with this program. If not, see <http://www.gnu.org/licenses/>.       *
 *                                                                            *
 ******************************************************************************/

package io.nekohasekai.sagernet.ui.profile

import android.annotation.SuppressLint
import android.content.DialogInterface
import android.graphics.Color
import android.os.Bundle
import android.view.Menu
import android.view.MenuItem
import androidx.activity.OnBackPressedCallback
import androidx.appcompat.app.AlertDialog
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.view.updatePadding
import cn.hutool.json.JSONObject
import com.blacksquircle.ui.editorkit.listener.OnChangeListener
import com.blacksquircle.ui.editorkit.model.ColorScheme
import com.blacksquircle.ui.language.base.model.SyntaxScheme
import com.blacksquircle.ui.language.json.JsonLanguage
import com.github.shadowsocks.plugin.Empty
import com.github.shadowsocks.plugin.fragment.AlertDialogFragment
import io.nekohasekai.sagernet.R
import io.nekohasekai.sagernet.database.DataStore
import io.nekohasekai.sagernet.databinding.LayoutEditConfigBinding
import io.nekohasekai.sagernet.ktx.getColorAttr
import io.nekohasekai.sagernet.ktx.onMainDispatcher
import io.nekohasekai.sagernet.ktx.runOnDefaultDispatcher
import io.nekohasekai.sagernet.ui.ThemedActivity
import io.nekohasekai.sagernet.utils.Theme
import androidx.core.graphics.toColorInt
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import io.nekohasekai.sagernet.SagerNet
import io.nekohasekai.sagernet.ktx.readableMessage

class ConfigEditActivity : ThemedActivity() {

    companion object {
        private const val KEY_CONFIG = "config"
    }

    private lateinit var binding: LayoutEditConfigBinding

    var config = ""
    var dirty = false

    val callback = object : OnBackPressedCallback(enabled = false) {
        override fun handleOnBackPressed() {
            if (ViewCompat.getRootWindowInsets(binding.editor)
                ?.isVisible(WindowInsetsCompat.Type.ime()) == true
                /* this also works on Android Emulator Android 5.0 anyway */
                ) {
                this@ConfigEditActivity.currentFocus?.windowToken?.let {
                    SagerNet.ime.hideSoftInputFromWindow(it, 0)
                }
            } else {
                UnsavedChangesDialogFragment().apply {
                    key()
                }.show(supportFragmentManager, null)
            }
        }
    }

    class UnsavedChangesDialogFragment : AlertDialogFragment<Empty, Empty>() {
        override fun AlertDialog.Builder.prepare(listener: DialogInterface.OnClickListener) {
            setTitle(R.string.unsaved_changes_prompt)
            setPositiveButton(android.R.string.ok) { _, _ ->
                (requireActivity() as ConfigEditActivity).saveAndExit()
            }
            setNegativeButton(android.R.string.cancel) { _, _ ->
                requireActivity().finish()
            }
        }
    }

    @SuppressLint("InlinedApi")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = LayoutEditConfigBinding.inflate(layoutInflater)

        setContentView(binding.root)

        ViewCompat.setOnApplyWindowInsetsListener(findViewById(R.id.layout_editor)) { v, insets ->
            val bars = insets.getInsets(
                WindowInsetsCompat.Type.systemBars()
                        or WindowInsetsCompat.Type.displayCutout()
            )
            v.updatePadding(
                left = bars.left,
            )
            insets
        }
        ViewCompat.setOnApplyWindowInsetsListener(binding.editor) { v, insets ->
            val bars = insets.getInsets(
                WindowInsetsCompat.Type.systemBars()
                        or WindowInsetsCompat.Type.displayCutout()
            )
            v.updatePadding(
                right = bars.right,
                bottom = bars.bottom,
            )
            insets
        }

        setSupportActionBar(findViewById(R.id.toolbar))
        supportActionBar?.apply {
            setTitle(R.string.config_settings)
            setDisplayHomeAsUpEnabled(true)
            setHomeAsUpIndicator(R.drawable.ic_navigation_close)
        }

        binding.editor.colorScheme = mkTheme()
        binding.editor.language = JsonLanguage()
        binding.editor.onChangeListener = OnChangeListener {
            config = binding.editor.text.toString()
            if (!dirty) {
                dirty = true
                DataStore.dirty = true
                callback.isEnabled = true
            }
        }
        binding.editor.setHorizontallyScrolling(true)

        runOnDefaultDispatcher {
            config = DataStore.serverConfig
            savedInstanceState?.getString(KEY_CONFIG)?.takeIf { it.isNotEmpty() }?.let {
                config = it
            }

            onMainDispatcher {
                binding.editor.setTextContent(config)
            }
        }

        onBackPressedDispatcher.addCallback(this, callback)
    }

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        outState.putString(KEY_CONFIG, config)
    }

    fun saveAndExit() {
        try {
            DataStore.serverConfig = JSONObject(config).toStringPretty()
        } catch (e: Exception) {
            DataStore.serverConfig = config
                MaterialAlertDialogBuilder(this).setTitle(R.string.error_title)
                .setMessage(e.readableMessage).show()
            return
        }
        finish()
    }

    override fun onSupportNavigateUp(): Boolean {
        if (!super.onSupportNavigateUp()) finish()
        return true
    }

    override fun onCreateOptionsMenu(menu: Menu): Boolean {
        menuInflater.inflate(R.menu.profile_apply_menu, menu)
        return true
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        when (item.itemId) {
            R.id.action_apply -> {
                saveAndExit()
                return true
            }
        }
        return super.onOptionsItemSelected(item)

    }

    fun mkTheme(): ColorScheme {
        val colorPrimary = getColorAttr(androidx.appcompat.R.attr.colorPrimary)
        val colorPrimaryDark = getColorAttr(androidx.appcompat.R.attr.colorPrimaryDark)

        return ColorScheme(
            textColor = when (Theme.getTheme()) {
                R.style.Theme_SagerNet_Black -> Color.WHITE
                R.style.Theme_SagerNet_LightBlack -> Color.BLACK
                else -> colorPrimary
            },
            backgroundColor = when (Theme.getTheme()) {
                R.style.Theme_SagerNet_Black -> Color.BLACK
                R.style.Theme_SagerNet_LightBlack -> Color.WHITE
                else -> if (Theme.usingNightMode()) Color.BLACK else Color.WHITE
            },
            gutterColor = colorPrimary,
            gutterDividerColor = if (Theme.usingNightMode()) Color.BLACK else Color.WHITE,
            gutterCurrentLineNumberColor = when (Theme.getTheme()) {
                R.style.Theme_SagerNet_LightBlack -> Color.BLACK
                else -> Color.WHITE
            },
            gutterTextColor = when (Theme.getTheme()) {
                R.style.Theme_SagerNet_LightBlack -> Color.BLACK
                else -> Color.WHITE
            },
            selectedLineColor = if (Theme.usingNightMode()) "#2C2C2C".toColorInt() else "#D3D3D3".toColorInt(),
            selectionColor = when (Theme.getTheme()) {
                R.style.Theme_SagerNet_Black -> "#4C4C4C".toColorInt()
                R.style.Theme_SagerNet_LightBlack -> "#B3B3B3".toColorInt()
                else -> colorPrimary
            },
            suggestionQueryColor = "#7CE0F3".toColorInt(),
            findResultBackgroundColor = "#5F5E5A".toColorInt(),
            delimiterBackgroundColor = "#5F5E5A".toColorInt(),
            syntaxScheme = SyntaxScheme(
                numberColor = "#BB8FF8".toColorInt(),
                operatorColor = if (Theme.usingNightMode()) Color.WHITE else Color.BLACK,
                keywordColor = "#EB347E".toColorInt(),
                typeColor = "#7FD0E4".toColorInt(),
                langConstColor = "#EB347E".toColorInt(),
                preprocessorColor = "#EB347E".toColorInt(),
                variableColor = "#7FD0E4".toColorInt(),
                methodColor = "#B6E951".toColorInt(),
                stringColor = when (Theme.getTheme()) {
                    R.style.Theme_SagerNet_Black -> Color.WHITE
                    R.style.Theme_SagerNet_LightBlack -> Color.BLACK
                    else -> colorPrimaryDark
                },
                commentColor = "#89826D".toColorInt(),
                tagColor = "#F8F8F8".toColorInt(),
                tagNameColor = "#EB347E".toColorInt(),
                attrNameColor = "#B6E951".toColorInt(),
                attrValueColor = "#EBE48C".toColorInt(),
                entityRefColor = "#BB8FF8".toColorInt()
            )
        )
    }

}