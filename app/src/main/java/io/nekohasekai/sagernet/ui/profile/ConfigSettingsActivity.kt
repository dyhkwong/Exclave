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

import android.os.Bundle
import androidx.preference.EditTextPreference
import com.takisoft.preferencex.PreferenceFragmentCompat
import com.takisoft.preferencex.SimpleMenuPreference
import io.nekohasekai.sagernet.Key
import io.nekohasekai.sagernet.R
import io.nekohasekai.sagernet.database.DataStore
import io.nekohasekai.sagernet.fmt.internal.ConfigBean
import io.nekohasekai.sagernet.ktx.onMainDispatcher
import io.nekohasekai.sagernet.ktx.runOnDefaultDispatcher
import io.nekohasekai.sagernet.widget.EditConfigPreference

class ConfigSettingsActivity : ProfileSettingsActivity<ConfigBean>() {

    override fun createEntity() = ConfigBean()

    var config = ""
    var dirty = false

    override fun ConfigBean.init() {
        DataStore.profileName = name
        DataStore.serverProtocol = type
        DataStore.serverConfig = content
        DataStore.serverAddress = serverAddresses
        config = content
    }

    override fun ConfigBean.serialize() {
        name = DataStore.profileName
        type = DataStore.serverProtocol
        content = config
        serverAddresses = DataStore.serverAddress
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        supportActionBar!!.setTitle(R.string.config_settings)
    }

    lateinit var editConfigPreference: EditConfigPreference
    override fun PreferenceFragmentCompat.createPreferences(
        savedInstanceState: Bundle?,
        rootKey: String?,
    ) {
        addPreferencesFromResource(R.xml.config_preferences)
        editConfigPreference = findPreference(Key.SERVER_CONFIG)!!
        val serverAddresses = findPreference<EditTextPreference>(Key.SERVER_ADDRESS)!!
        val serverProtocol = findPreference<SimpleMenuPreference>(Key.SERVER_PROTOCOL)!!
        fun updateProtocol(protocol: String) {
            serverAddresses.isVisible = protocol == "v2ray_outbound"
        }
        updateProtocol(DataStore.serverProtocol)
        serverProtocol.setOnPreferenceChangeListener { _, newValue ->
            updateProtocol(newValue as String)
            true
        }
    }

    override fun onResume() {
        super.onResume()

        if (::editConfigPreference.isInitialized) {
            runOnDefaultDispatcher {
                val newConfig = DataStore.serverConfig

                if (newConfig != config) {
                    config = newConfig

                    onMainDispatcher {
                        editConfigPreference.notifyChanged()
                    }
                }
            }
        }
    }

}