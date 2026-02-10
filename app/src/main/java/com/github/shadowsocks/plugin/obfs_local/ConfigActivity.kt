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
import android.view.MenuItem
import androidx.activity.OnBackPressedCallback
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.widget.Toolbar
import com.github.shadowsocks.plugin.ConfigurationActivity
import com.github.shadowsocks.plugin.PluginOptions
import io.nekohasekai.sagernet.R

class ConfigActivity : ConfigurationActivity(), Toolbar.OnMenuItemClickListener {
    companion object {
        const val KEY_DIRTY = "dirty"
    }

    private val child by lazy { supportFragmentManager.findFragmentById(R.id.content) as ConfigFragment }
    private var oldOptions : PluginOptions? = null

    override val onBackPressedCallback = object : OnBackPressedCallback(enabled = false) {
        override fun handleOnBackPressed() {
            onFinish()
        }
    }
    var dirty = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.layout_obfs_local)

        findViewById<Toolbar>(R.id.toolbar).apply {
            title = "Simple obfuscation"
            setNavigationIcon(R.drawable.ic_navigation_close)
            setNavigationOnClickListener { onFinish() }
            inflateMenu(R.menu.plugin_menu)
            setOnMenuItemClickListener(this@ConfigActivity)
        }

        savedInstanceState?.getBoolean(KEY_DIRTY)?.let {
            dirty = it
            onBackPressedCallback.isEnabled = it
        }
    }

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        outState.putBoolean(KEY_DIRTY, dirty)
    }

    override fun onInitializePluginOptions(options: PluginOptions) {
        oldOptions = options
        child.onInitializePluginOptions(options)
    }

    override fun onMenuItemClick(item: MenuItem?) = when (item?.itemId) {
        R.id.action_apply -> {
            saveChanges(child.options)
            finish()
            true
        }
        else -> false
    }

    private fun onFinish() {
        if (child.options != oldOptions) {
            AlertDialog.Builder(this).run {
                setTitle(R.string.unsaved_changes_prompt)
                setPositiveButton(android.R.string.ok) { _, _ ->
                    saveChanges(child.options)
                    finish()
                }
                setNegativeButton(android.R.string.cancel) { _, _ ->
                    finish()
                }
                create()
            }.show()
        } else {
            finish()
        }
    }
}
