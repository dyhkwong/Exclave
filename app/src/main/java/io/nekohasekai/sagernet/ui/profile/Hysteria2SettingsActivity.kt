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
import io.nekohasekai.sagernet.Key
import io.nekohasekai.sagernet.R
import io.nekohasekai.sagernet.database.DataStore
import io.nekohasekai.sagernet.database.preference.EditTextPreferenceModifiers
import io.nekohasekai.sagernet.fmt.hysteria2.Hysteria2Bean
import io.nekohasekai.sagernet.ktx.unwrapIDN

class Hysteria2SettingsActivity : ProfileSettingsActivity<Hysteria2Bean>() {

    override fun createEntity() = Hysteria2Bean()

    override fun Hysteria2Bean.init() {
        DataStore.profileName = name
        DataStore.serverAddress = serverAddress
        DataStore.serverPort = serverPort
        DataStore.serverObfs = obfs
        DataStore.serverPassword = auth
        DataStore.serverSNI = sni
        DataStore.serverCertificates = certificates
        DataStore.serverPinnedCertificateChain = pinnedPeerCertificateChainSha256
        DataStore.serverPinnedCertificatePublicKey = pinnedPeerCertificatePublicKeySha256
        DataStore.serverPinnedCertificate = pinnedPeerCertificateSha256
        DataStore.serverAllowInsecure = allowInsecure
        DataStore.serverUploadSpeed = uploadMbps
        DataStore.serverDownloadSpeed = downloadMbps
        DataStore.serverDisableMtuDiscovery = disableMtuDiscovery
        DataStore.serverInitStreamReceiveWindow = initStreamReceiveWindow
        DataStore.serverMaxStreamReceiveWindow = maxStreamReceiveWindow
        DataStore.serverInitConnReceiveWindow = initConnReceiveWindow
        DataStore.serverMaxConnReceiveWindow = maxConnReceiveWindow
        DataStore.serverPorts = serverPorts
        DataStore.serverHopInterval = hopInterval
        DataStore.serverEchConfig = echConfig
        DataStore.serverMtlsCertificate = mtlsCertificate
        DataStore.serverMtlsCertificatePrivateKey = mtlsCertificatePrivateKey
    }

    override fun Hysteria2Bean.serialize() {
        name = DataStore.profileName
        serverAddress = DataStore.serverAddress.unwrapIDN()
        serverPort = DataStore.serverPort
        obfs = DataStore.serverObfs
        auth = DataStore.serverPassword
        sni = DataStore.serverSNI
        certificates = DataStore.serverCertificates
        pinnedPeerCertificateChainSha256 = DataStore.serverPinnedCertificateChain
        pinnedPeerCertificatePublicKeySha256 = DataStore.serverPinnedCertificatePublicKey
        pinnedPeerCertificateSha256 = DataStore.serverPinnedCertificate
        allowInsecure = DataStore.serverAllowInsecure
        uploadMbps = DataStore.serverUploadSpeed
        downloadMbps = DataStore.serverDownloadSpeed
        disableMtuDiscovery = DataStore.serverDisableMtuDiscovery
        initStreamReceiveWindow = DataStore.serverInitStreamReceiveWindow
        maxStreamReceiveWindow = DataStore.serverMaxStreamReceiveWindow
        initConnReceiveWindow = DataStore.serverInitConnReceiveWindow
        maxConnReceiveWindow = DataStore.serverMaxConnReceiveWindow
        serverPorts = DataStore.serverPorts
        hopInterval = DataStore.serverHopInterval
        echConfig = DataStore.serverEchConfig
        mtlsCertificate = DataStore.serverMtlsCertificate
        mtlsCertificatePrivateKey = DataStore.serverMtlsCertificatePrivateKey
    }

    override fun PreferenceFragmentCompat.createPreferences(
        savedInstanceState: Bundle?,
        rootKey: String?,
    ) {
        addPreferencesFromResource(R.xml.hysteria2_preferences)

        findPreference<EditTextPreference>(Key.SERVER_HOP_INTERVAL)!!.apply {
            setOnBindEditTextListener(EditTextPreferenceModifiers.Number)
        }

        findPreference<EditTextPreference>(Key.SERVER_UPLOAD_SPEED)!!.apply {
            setOnBindEditTextListener(EditTextPreferenceModifiers.Number)
        }
        findPreference<EditTextPreference>(Key.SERVER_DOWNLOAD_SPEED)!!.apply {
            setOnBindEditTextListener(EditTextPreferenceModifiers.Number)
        }

        findPreference<EditTextPreference>(Key.SERVER_INIT_STREAM_RECEIVE_WINDOW)!!.apply {
            setOnBindEditTextListener(EditTextPreferenceModifiers.Number)
        }
        findPreference<EditTextPreference>(Key.SERVER_MAX_STREAM_RECEIVE_WINDOW)!!.apply {
            setOnBindEditTextListener(EditTextPreferenceModifiers.Number)
        }
        findPreference<EditTextPreference>(Key.SERVER_INIT_CONN_RECEIVE_WINDOW)!!.apply {
            setOnBindEditTextListener(EditTextPreferenceModifiers.Number)
        }
        findPreference<EditTextPreference>(Key.SERVER_MAX_CONN_RECEIVE_WINDOW)!!.apply {
            setOnBindEditTextListener(EditTextPreferenceModifiers.Number)
        }

        findPreference<EditTextPreference>(Key.SERVER_PASSWORD)!!.apply {
            summaryProvider = PasswordSummaryProvider
        }
        findPreference<EditTextPreference>(Key.SERVER_OBFS)!!.apply {
            summaryProvider = PasswordSummaryProvider
        }
    }

}