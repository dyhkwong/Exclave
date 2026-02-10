/*******************************************************************************
 *                                                                             *
 *  Copyright (C) 2019 by Max Lv <max.c.lv@gmail.com>                          *
 *  Copyright (C) 2019 by Mygod Studio <contact-shadowsocks-android@mygod.be>  *
 *                                                                             *
 *  This program is free software: you can redistribute it and/or modify       *
 *  it under the terms of the GNU General Public License as published by       *
 *  the Free Software Foundation, either version 3 of the License, or          *
 *  (at your option) any later version.                                        *
 *                                                                             *
 *  This program is distributed in the hope that it will be useful,            *
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of             *
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the              *
 *  GNU General Public License for more details.                               *
 *                                                                             *
 *  You should have received a copy of the GNU General Public License          *
 *  along with this program. If not, see <http://www.gnu.org/licenses/>.       *
 *                                                                             *
 *******************************************************************************/

package com.github.shadowsocks.plugin.obfs_local

import android.os.Bundle
import android.text.InputType
import android.view.View
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.view.updatePadding
import androidx.preference.EditTextPreference
import androidx.preference.ListPreference
import androidx.preference.Preference
import androidx.preference.PreferenceFragmentCompat
import com.github.shadowsocks.plugin.PluginOptions
import io.nekohasekai.sagernet.R

class ConfigFragment : PreferenceFragmentCompat(), Preference.OnPreferenceChangeListener {
    private val obfs by lazy { findPreference<ListPreference>("obfs")!! }
    private val obfsHost by lazy { findPreference<EditTextPreference>("obfs-host")!! }

    val options get() = PluginOptions().apply {
        put("obfs", obfs.value)
        putWithDefault("obfs-host", obfsHost.text, "cloudfront.net")
    }

    fun onInitializePluginOptions(options: PluginOptions) {
        obfs.value = when {
            options["mode"] == "http" -> "http"
            options["obfs"] == "tls" -> "tls"
            else -> "http"
        }
        obfsHost.text = options["host"] ?: "cloudfront.net"
    }

    override fun onCreatePreferences(savedInstanceState: Bundle?, rootKey: String?) {
        addPreferencesFromResource(R.xml.obfs_local_config)
        obfs.onPreferenceChangeListener = this
        obfsHost.setOnBindEditTextListener {
            it.inputType = InputType.TYPE_TEXT_VARIATION_URI
            it.setSelection(it.text.length)
        }
        obfsHost.onPreferenceChangeListener = this
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        ViewCompat.setOnApplyWindowInsetsListener(listView) { v, insets ->
            val bars = insets.getInsets(
                WindowInsetsCompat.Type.systemBars()
                        or WindowInsetsCompat.Type.displayCutout()
            )
            v.updatePadding(
                left = bars.left,
                right = bars.right,
                bottom = bars.bottom,
            )
            insets
        }
    }

    override fun onPreferenceChange(preference: Preference, newValue: Any?): Boolean {
        val oldValue = when (preference) {
            is EditTextPreference -> preference.text
            is ListPreference -> preference.value
            else -> null
        }
        if (oldValue != newValue) {
            (requireActivity() as? ConfigActivity)?.let {
                it.dirty = true
                it.onBackPressedCallback.isEnabled = true
            }
        }
        return true
    }
}
