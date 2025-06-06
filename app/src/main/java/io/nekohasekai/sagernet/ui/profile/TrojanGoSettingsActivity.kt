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
import androidx.preference.PreferenceCategory
import androidx.preference.SwitchPreference
import com.takisoft.preferencex.PreferenceFragmentCompat
import com.takisoft.preferencex.SimpleMenuPreference
import io.nekohasekai.sagernet.Key
import io.nekohasekai.sagernet.R
import io.nekohasekai.sagernet.database.DataStore
import io.nekohasekai.sagernet.database.preference.EditTextPreferenceModifiers
import io.nekohasekai.sagernet.fmt.trojan_go.TrojanGoBean
import io.nekohasekai.sagernet.ktx.*

class TrojanGoSettingsActivity : ProfileSettingsActivity<TrojanGoBean>() {

    override fun createEntity() = TrojanGoBean()

    override fun TrojanGoBean.init() {
        DataStore.profileName = name
        DataStore.serverAddress = serverAddress
        DataStore.serverPort = serverPort
        DataStore.serverPassword = password
        DataStore.serverSNI = sni
        DataStore.serverAllowInsecure = allowInsecure
        DataStore.serverNetwork = type
        DataStore.serverHost = host
        DataStore.serverPath = path
        if (encryption.startsWith("ss;")) {
            DataStore.serverEncryption = "ss"
            DataStore.serverMethod = encryption.substringAfter(";").substringBefore(":")
            DataStore.serverPassword1 = encryption.substringAfter(":")
        } else {
            DataStore.serverEncryption = encryption
        }
        DataStore.serverUTLSFingerprint = utlsFingerprint
        DataStore.serverMux = mux
        DataStore.serverMuxConcurrency = muxConcurrency
    }

    override fun TrojanGoBean.serialize() {
        name = DataStore.profileName
        serverAddress = DataStore.serverAddress.unwrapIDN()
        serverPort = DataStore.serverPort
        password = DataStore.serverPassword
        sni = DataStore.serverSNI
        allowInsecure = DataStore.serverAllowInsecure
        type = DataStore.serverNetwork
        host = DataStore.serverHost
        path = DataStore.serverPath
        encryption = when (val security = DataStore.serverEncryption) {
            "ss" -> {
                "ss;" + DataStore.serverMethod + ":" + DataStore.serverPassword1
            }
            else -> {
                security
            }
        }
        utlsFingerprint = DataStore.serverUTLSFingerprint
        mux = DataStore.serverMux
        muxConcurrency = DataStore.serverMuxConcurrency
    }

    lateinit var network: SimpleMenuPreference
    lateinit var encryprtion: SimpleMenuPreference
    lateinit var wsCategory: PreferenceCategory
    lateinit var ssCategory: PreferenceCategory
    lateinit var method: SimpleMenuPreference
    lateinit var utlsFingerprint: SimpleMenuPreference
    lateinit var mux: SwitchPreference
    lateinit var muxConcurrency: EditTextPreference

    val trojanGoMethods = app.resources.getStringArray(R.array.trojan_go_methods_value)
    val trojanGoNetworks = app.resources.getStringArray(R.array.trojan_go_networks_value)

    override fun PreferenceFragmentCompat.createPreferences(
        savedInstanceState: Bundle?,
        rootKey: String?,
    ) {
        addPreferencesFromResource(R.xml.trojan_go_preferences)
        findPreference<EditTextPreference>(Key.SERVER_PORT)!!.apply {
            setOnBindEditTextListener(EditTextPreferenceModifiers.Port)
        }
        findPreference<EditTextPreference>(Key.SERVER_PASSWORD)!!.apply {
            summaryProvider = PasswordSummaryProvider
        }
        findPreference<EditTextPreference>(Key.SERVER_PASSWORD1)!!.apply {
            summaryProvider = PasswordSummaryProvider
        }
        wsCategory = findPreference(Key.SERVER_WS_CATEGORY)!!
        ssCategory = findPreference(Key.SERVER_SS_CATEGORY)!!
        method = findPreference(Key.SERVER_METHOD)!!

        network = findPreference(Key.SERVER_NETWORK)!!

        if (network.value !in trojanGoNetworks) {
            network.value = trojanGoNetworks[0]
        }

        updateNetwork(network.value)
        network.setOnPreferenceChangeListener { _, newValue ->
            updateNetwork(newValue as String)
            true
        }
        encryprtion = findPreference(Key.SERVER_ENCRYPTION)!!
        updateEncryption(encryprtion.value)
        encryprtion.setOnPreferenceChangeListener { _, newValue ->
            updateEncryption(newValue as String)
            true
        }
        utlsFingerprint = findPreference(Key.SERVER_UTLS_FINGERPRINT)!!

        mux = findPreference(Key.SERVER_MUX)!!
        muxConcurrency = findPreference(Key.SERVER_MUX_CONCURRENCY)!!
        muxConcurrency.isVisible = mux.isChecked
        muxConcurrency.setOnBindEditTextListener(EditTextPreferenceModifiers.Mux)
        mux.setOnPreferenceChangeListener { _, newValue ->
            muxConcurrency.isVisible = newValue as Boolean
            true
        }
    }

    fun updateNetwork(newNet: String) {
        when (newNet) {
            "ws" -> {
                wsCategory.isVisible = true
            }
            else -> {
                wsCategory.isVisible = false
            }
        }
    }

    fun updateEncryption(encryption: String) {
        when (encryption) {
            "ss" -> {
                ssCategory.isVisible = true

                if (method.value !in trojanGoMethods) {
                    method.value = trojanGoMethods[0]
                }
            }
            else -> {
                ssCategory.isVisible = false
            }
        }
    }

}