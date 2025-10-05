/******************************************************************************
 *                                                                            *
 * Copyright (C) 2025 by dyhkwong                                             *
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
import io.nekohasekai.sagernet.Key
import io.nekohasekai.sagernet.R
import io.nekohasekai.sagernet.database.DataStore
import io.nekohasekai.sagernet.database.preference.EditTextPreferenceModifiers
import io.nekohasekai.sagernet.fmt.http3.Http3Bean
import io.nekohasekai.sagernet.ktx.unwrapIDN

class Http3SettingsActivity : ProfileSettingsActivity<Http3Bean>() {

    override fun createEntity() = Http3Bean()

    override fun Http3Bean.init() {
        DataStore.profileName = name
        DataStore.serverAddress = serverAddress
        DataStore.serverPort = serverPort
        DataStore.serverUsername = username
        DataStore.serverPassword = password
        DataStore.serverSNI = sni
        DataStore.serverCertificates = certificates
        DataStore.serverPinnedCertificateChain = pinnedPeerCertificateChainSha256
        DataStore.serverPinnedCertificatePublicKey = pinnedPeerCertificatePublicKeySha256
        DataStore.serverPinnedCertificate = pinnedPeerCertificateSha256
        DataStore.serverEchConfig = echConfig
        DataStore.serverAllowInsecure = allowInsecure
        DataStore.serverMtlsCertificate = mtlsCertificate
        DataStore.serverMtlsCertificatePrivateKey = mtlsCertificatePrivateKey
    }

    override fun Http3Bean.serialize() {
        name = DataStore.profileName
        serverAddress = DataStore.serverAddress.unwrapIDN()
        serverPort = DataStore.serverPort
        username = DataStore.serverUsername
        password = DataStore.serverPassword
        sni = DataStore.serverSNI
        certificates = DataStore.serverCertificates
        pinnedPeerCertificateChainSha256 = DataStore.serverPinnedCertificateChain
        pinnedPeerCertificatePublicKeySha256 = DataStore.serverPinnedCertificatePublicKey
        pinnedPeerCertificateSha256 = DataStore.serverPinnedCertificate
        echConfig = DataStore.serverEchConfig
        allowInsecure = DataStore.serverAllowInsecure
        mtlsCertificate = DataStore.serverMtlsCertificate
        mtlsCertificatePrivateKey = DataStore.serverMtlsCertificatePrivateKey
    }

    override fun PreferenceFragmentCompat.createPreferences(
        savedInstanceState: Bundle?,
        rootKey: String?,
    ) {
        addPreferencesFromResource(R.xml.http3_preferences)
        findPreference<EditTextPreference>(Key.SERVER_PORT)!!.apply {
            setOnBindEditTextListener(EditTextPreferenceModifiers.Port)
        }
        findPreference<EditTextPreference>(Key.SERVER_PASSWORD)!!.apply {
            summaryProvider = PasswordSummaryProvider
        }
    }

}
