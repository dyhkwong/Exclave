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
import io.nekohasekai.sagernet.fmt.brook.BrookBean
import io.nekohasekai.sagernet.ktx.app
import io.nekohasekai.sagernet.ktx.unwrapIDN

class BrookSettingsActivity : ProfileSettingsActivity<BrookBean>() {

    override fun createEntity() = BrookBean()

    override fun BrookBean.init() {
        DataStore.profileName = name
        DataStore.serverAddress = serverAddress
        DataStore.serverPort = serverPort
        DataStore.serverProtocol = protocol
        DataStore.serverPassword = password
        DataStore.serverPath = wsPath
        DataStore.serverAllowInsecure = insecure
        DataStore.serverWithoutBrookProtocol = withoutBrookProtocol
        DataStore.serverBrookUdpOverTcp = udpovertcp
        DataStore.serverBrookTlsFingerprint = tlsfingerprint
        DataStore.serverBrookFragment = fragment
        DataStore.serverSNI = sni
        DataStore.serverBrookUdpOverStream = udpoverstream
        DataStore.serverBrookClientHkdfInfo = clientHKDFInfo
        DataStore.serverBrookServerHkdfInfo = serverHKDFInfo
        DataStore.serverBrookToken = token
        DataStore.serverCertificates = ca
    }

    override fun BrookBean.serialize() {
        name = DataStore.profileName
        serverAddress = DataStore.serverAddress.unwrapIDN()
        serverPort = DataStore.serverPort
        password = DataStore.serverPassword
        protocol = DataStore.serverProtocol
        wsPath = DataStore.serverPath
        insecure = DataStore.serverAllowInsecure
        withoutBrookProtocol = DataStore.serverWithoutBrookProtocol
        udpovertcp = DataStore.serverBrookUdpOverTcp
        tlsfingerprint = DataStore.serverBrookTlsFingerprint
        fragment = DataStore.serverBrookFragment
        sni = DataStore.serverSNI
        udpoverstream = DataStore.serverBrookUdpOverStream
        clientHKDFInfo = DataStore.serverBrookClientHkdfInfo
        serverHKDFInfo = DataStore.serverBrookServerHkdfInfo
        token = DataStore.serverBrookToken
        ca = DataStore.serverCertificates
    }

    lateinit var protocol: SimpleMenuPreference
    val protocolValue = app.resources.getStringArray(R.array.brook_protocol_value)
    lateinit var category: PreferenceCategory
    lateinit var insecure: SwitchPreference
    lateinit var wsPath: EditTextPreference
    lateinit var tlsfingerprint: SimpleMenuPreference
    lateinit var fragment: EditTextPreference
    lateinit var sni: EditTextPreference
    lateinit var udpovertcp: SwitchPreference
    lateinit var udpoverstream: SwitchPreference
    lateinit var withoutBrookProtocol: SwitchPreference
    lateinit var ca: EditTextPreference
    lateinit var token: EditTextPreference

    override fun PreferenceFragmentCompat.createPreferences(
        savedInstanceState: Bundle?,
        rootKey: String?,
    ) {
        addPreferencesFromResource(R.xml.brook_preferences)

        findPreference<EditTextPreference>(Key.SERVER_PORT)!!.apply {
            setOnBindEditTextListener(EditTextPreferenceModifiers.Port)
        }
        findPreference<EditTextPreference>(Key.SERVER_PASSWORD)!!.apply {
            summaryProvider = PasswordSummaryProvider
        }
        findPreference<EditTextPreference>(Key.SERVER_BROOK_TOKEN)!!.apply {
            summaryProvider = PasswordSummaryProvider
        }

        protocol = findPreference(Key.SERVER_PROTOCOL)!!
        insecure = findPreference(Key.SERVER_ALLOW_INSECURE)!!
        wsPath = findPreference(Key.SERVER_PATH)!!
        tlsfingerprint = findPreference(Key.SERVER_BROOK_TLS_FINGERPRINT)!!
        fragment = findPreference(Key.SERVER_BROOK_FRAGMENT)!!
        sni = findPreference(Key.SERVER_SNI)!!
        udpovertcp = findPreference(Key.SERVER_BROOK_UDP_OVER_TCP)!!
        udpoverstream = findPreference(Key.SERVER_BROOK_UDP_OVER_STREAM)!!
        withoutBrookProtocol = findPreference(Key.SERVER_WITHOUT_BROOK_PROTOCOL)!!
        ca = findPreference(Key.SERVER_CERTIFICATES)!!

        if (protocol.value !in protocolValue) {
            protocol.value = protocolValue[0]
        }
        updateProtocol(protocol.value)
        protocol.setOnPreferenceChangeListener { _, newValue ->
            updateProtocol(newValue as String)
            true
        }
    }

    fun updateProtocol(value: String) {
        insecure.isVisible = value == "wss" || value == "quic"
        wsPath.isVisible = value.startsWith("ws")
        tlsfingerprint.isVisible = value == "wss"
        fragment.isVisible = value == "wss"
        sni.isVisible = value == "wss" || value == "quic"
        udpovertcp.isVisible = value == ""
        udpoverstream.isVisible = value == "quic"
        withoutBrookProtocol.isVisible = value == "ws" || value == "wss" || value == "quic"
        ca.isVisible = value == "wss" || value == "quic"
    }

}