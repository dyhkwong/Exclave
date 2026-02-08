/******************************************************************************
 *                                                                            *
 * Copyright (C) 2026  dyhkwong                                               *
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
import io.nekohasekai.sagernet.database.preference.EditTextPreferenceModifiers
import io.nekohasekai.sagernet.fmt.trusttunnel.TrustTunnelBean
import io.nekohasekai.sagernet.ktx.unwrapIDN

class TrustTunnelSettingsActivity : ProfileSettingsActivity<TrustTunnelBean>() {

    override fun createEntity() = TrustTunnelBean()

    override fun TrustTunnelBean.init() {
        DataStore.profileName = name
        DataStore.serverAddress = serverAddress
        DataStore.serverPort = serverPort
        DataStore.serverProtocol = protocol
        DataStore.serverUsername = username
        DataStore.serverPassword = password
        DataStore.serverSNI = sni
        DataStore.serverCertificates = certificate
        DataStore.serverUTLSFingerprint = utlsFingerprint
        DataStore.serverAllowInsecure = allowInsecure
    }

    override fun TrustTunnelBean.serialize() {
        name = DataStore.profileName
        serverAddress = DataStore.serverAddress.unwrapIDN()
        serverPort = DataStore.serverPort
        protocol = DataStore.serverProtocol
        username = DataStore.serverUsername
        password = DataStore.serverPassword
        sni = DataStore.serverSNI
        certificate = DataStore.serverCertificates
        utlsFingerprint = DataStore.serverUTLSFingerprint
        allowInsecure = DataStore.serverAllowInsecure
    }

    override fun PreferenceFragmentCompat.createPreferences(
        savedInstanceState: Bundle?,
        rootKey: String?,
    ) {
        addPreferencesFromResource(R.xml.trusttunnel_preferences)
        findPreference<EditTextPreference>(Key.SERVER_PORT)!!.apply {
            setOnBindEditTextListener(EditTextPreferenceModifiers.Port)
        }
        findPreference<EditTextPreference>(Key.SERVER_PASSWORD)!!.apply {
            summaryProvider = PasswordSummaryProvider
        }
        val utlsFingerprint = findPreference<SimpleMenuPreference>(Key.SERVER_UTLS_FINGERPRINT)!!
        val protocol = findPreference<SimpleMenuPreference>(Key.SERVER_PROTOCOL)!!
        utlsFingerprint.isVisible = protocol.value == "https"
        protocol.setOnPreferenceChangeListener { _, newValue ->
            newValue as String
            utlsFingerprint.isVisible = newValue == "https"
            true
        }
    }

}