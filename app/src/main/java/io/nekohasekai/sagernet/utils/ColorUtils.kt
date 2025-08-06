/******************************************************************************
 *                                                                            *
 * Copyright (C) 2022 by nekohasekai <contact-sagernet@sekai.icu>             *
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

package io.nekohasekai.sagernet.utils

import android.content.Context
import android.graphics.Color
import android.graphics.Typeface
import android.text.ParcelableSpan
import android.text.Spannable
import android.text.SpannableString
import android.text.style.ForegroundColorSpan
import android.text.style.StyleSpan
import android.text.style.UnderlineSpan
import androidx.core.content.ContextCompat
import io.nekohasekai.sagernet.R
import java.util.Stack

// https://github.com/SagerNet/sing-box-for-android/blob/7384b97fdc36a9956f3d43174b89e4697a8ea47d/app/src/main/java/io/nekohasekai/sfa/utils/ColorUtils.kt
object ColorUtils {

    private val ansiRegex by lazy { Regex("\u001B\\[[;\\d]*m") }

    fun ansiEscapeToSpannable(context: Context, text: String): Spannable {
        val spannable = SpannableString(text.replace(ansiRegex, ""))
        val stack = Stack<AnsiSpan>()
        val spans = mutableListOf<AnsiSpan>()
        val matches = ansiRegex.findAll(text)
        var offset = 0

        matches.forEach { result ->
            val stringCode = result.value
            val start = result.range.last
            val end = result.range.last + 1
            val ansiInstruction = AnsiInstruction(context, stringCode)
            offset += stringCode.length
            if (ansiInstruction.decorationCode == "0" && stack.isNotEmpty()) {
                spans.add(stack.pop().copy(end = end - offset))
            } else {
                val span = AnsiSpan(
                    AnsiInstruction(context, stringCode),
                    start - if (offset > start) start else offset - 1,
                    0
                )
                stack.push(span)
            }
        }

        spans.forEach { ansiSpan ->
            ansiSpan.instruction.spans.forEach {
                spannable.setSpan(
                    it,
                    ansiSpan.start,
                    ansiSpan.end,
                    Spannable.SPAN_EXCLUSIVE_INCLUSIVE
                )
            }
        }

        return spannable
    }

    private data class AnsiSpan(
        val instruction: AnsiInstruction, val start: Int, val end: Int,
    )

    private class AnsiInstruction(context: Context, code: String) {

        val spans: List<ParcelableSpan> by lazy {
            listOfNotNull(
                getSpan(colorCode, context), getSpan(decorationCode, context)
            )
        }

        var colorCode: String? = null
            private set

        var decorationCode: String? = null
            private set

        init {
            val colorCodes = code.substringAfter('[').substringBefore('m').split(';')

            when (colorCodes.size) {
                3 -> {
                    colorCode = colorCodes[1]
                    decorationCode = colorCodes[2]
                }

                2 -> {
                    colorCode = colorCodes[0]
                    decorationCode = colorCodes[1]
                }

                1 -> decorationCode = colorCodes[0]
            }
        }
    }

    private fun getSpan(code: String?, context: Context): ParcelableSpan? = when (code) {
        "0", null -> null
        "1" -> StyleSpan(Typeface.NORMAL)
        "3" -> StyleSpan(Typeface.ITALIC)
        "4" -> UnderlineSpan()
        "30" -> ForegroundColorSpan(ContextCompat.getColor(context, R.color.ansi_black))
        "31" -> ForegroundColorSpan(ContextCompat.getColor(context, R.color.ansi_red))
        "32" -> ForegroundColorSpan(ContextCompat.getColor(context, R.color.ansi_green))
        "33" -> ForegroundColorSpan(ContextCompat.getColor(context, R.color.ansi_yellow))
        "34" -> ForegroundColorSpan(ContextCompat.getColor(context, R.color.ansi_blue))
        "35" -> ForegroundColorSpan(ContextCompat.getColor(context, R.color.ansi_magenta))
        "36" -> ForegroundColorSpan(ContextCompat.getColor(context, R.color.ansi_cyan))
        "37" -> ForegroundColorSpan(ContextCompat.getColor(context, R.color.ansi_white))
        "90" -> ForegroundColorSpan(ContextCompat.getColor(context, R.color.ansi_bright_black))
        "91" -> ForegroundColorSpan(ContextCompat.getColor(context, R.color.ansi_bright_red))
        "92" -> ForegroundColorSpan(ContextCompat.getColor(context, R.color.ansi_bright_green))
        "93" -> ForegroundColorSpan(ContextCompat.getColor(context, R.color.ansi_bright_yellow))
        "94" -> ForegroundColorSpan(ContextCompat.getColor(context, R.color.ansi_bright_blue))
        "95" -> ForegroundColorSpan(ContextCompat.getColor(context, R.color.ansi_bright_magenta))
        "96" -> ForegroundColorSpan(ContextCompat.getColor(context, R.color.ansi_bright_cyan))
        "97" -> ForegroundColorSpan(ContextCompat.getColor(context, R.color.ansi_bright_white))
        else -> {
            var codeInt = code.toIntOrNull()
            if (codeInt != null) {
                codeInt %= 125
                val row = codeInt / 36
                val column = codeInt % 36
                ForegroundColorSpan(Color.rgb(row * 51, column / 6 * 51, column % 6 * 51))
            } else {
                null
            }
        }
    }
}