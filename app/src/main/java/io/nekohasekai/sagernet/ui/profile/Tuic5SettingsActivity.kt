/******************************************************************************
 *                                                                            *
 * Copyright (C) 2023  dyhkwong                                               *
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
 * along with this program. If not, see <https://www.gnu.org/licenses/>.      *
 *                                                                            *
 ******************************************************************************/

package io.nekohasekai.sagernet.ui.profile

import android.os.Bundle
import androidx.preference.EditTextPreference
import androidx.preference.PreferenceCategory
import androidx.preference.SwitchPreference
import com.takisoft.preferencex.PreferenceFragmentCompat
import io.nekohasekai.sagernet.Key
import io.nekohasekai.sagernet.R
import io.nekohasekai.sagernet.database.DataStore
import io.nekohasekai.sagernet.fmt.tuic5.Tuic5Bean
import io.nekohasekai.sagernet.ktx.unwrapIDN

class Tuic5SettingsActivity : ProfileSettingsActivity<Tuic5Bean>() {

    override fun createEntity() = Tuic5Bean()

    override fun Tuic5Bean.init() {
        DataStore.profileName = name
        DataStore.serverAddress = serverAddress
        DataStore.serverPort = serverPort
        DataStore.serverUserId = uuid
        DataStore.serverPassword = password
        DataStore.serverALPN = alpn
        DataStore.serverCertificates = certificates
        DataStore.serverUDPRelayMode = udpRelayMode
        DataStore.serverCongestionController = congestionControl
        DataStore.serverDisableSNI = disableSNI
        DataStore.serverSNI = sni
        DataStore.serverReduceRTT = zeroRTTHandshake
        DataStore.serverMTU = mtu
        DataStore.serverAllowInsecure = allowInsecure
        DataStore.serverPinnedCertificateChain = pinnedPeerCertificateChainSha256
        DataStore.serverPinnedCertificatePublicKey = pinnedPeerCertificatePublicKeySha256
        DataStore.serverPinnedCertificate = pinnedPeerCertificateSha256
        DataStore.serverMtlsCertificate = mtlsCertificate
        DataStore.serverMtlsCertificatePrivateKey = mtlsCertificatePrivateKey
        DataStore.serverEchConfig = echConfig
        DataStore.serverSingUot = singUDPOverStream
    }

    override fun Tuic5Bean.serialize() {
        name = DataStore.profileName
        serverAddress = DataStore.serverAddress.unwrapIDN()
        serverPort = DataStore.serverPort
        uuid = DataStore.serverUserId
        password = DataStore.serverPassword
        alpn = DataStore.serverALPN
        certificates = DataStore.serverCertificates
        udpRelayMode = DataStore.serverUDPRelayMode
        congestionControl = DataStore.serverCongestionController
        disableSNI = DataStore.serverDisableSNI
        sni = DataStore.serverSNI
        zeroRTTHandshake = DataStore.serverReduceRTT
        mtu = DataStore.serverMTU
        allowInsecure = DataStore.serverAllowInsecure
        pinnedPeerCertificateChainSha256 = DataStore.serverPinnedCertificateChain
        pinnedPeerCertificatePublicKeySha256 = DataStore.serverPinnedCertificatePublicKey
        pinnedPeerCertificateSha256 = DataStore.serverPinnedCertificate
        mtlsCertificate = DataStore.serverMtlsCertificate
        mtlsCertificatePrivateKey = DataStore.serverMtlsCertificatePrivateKey
        echConfig = DataStore.serverEchConfig
        singUDPOverStream = DataStore.serverSingUot
    }

    override fun PreferenceFragmentCompat.createPreferences(
        savedInstanceState: Bundle?,
        rootKey: String?,
    ) {
        addPreferencesFromResource(R.xml.tuic5_preferences)

        val disableSNI = findPreference<SwitchPreference>(Key.SERVER_DISABLE_SNI)!!
        val sni = findPreference<EditTextPreference>(Key.SERVER_SNI)!!
        sni.isEnabled = !disableSNI.isChecked
        disableSNI.setOnPreferenceChangeListener { _, newValue ->
            sni.isEnabled = !(newValue as Boolean)
            true
        }

        findPreference<EditTextPreference>(Key.SERVER_PASSWORD)!!.apply {
            summaryProvider = PasswordSummaryProvider
        }

        findPreference<PreferenceCategory>(Key.SERVER_SING_UOT_CATEGORY)!!.isVisible =
        DataStore.experimentalFlags.split("\n").any { it == "singuot=true" }
    }

}