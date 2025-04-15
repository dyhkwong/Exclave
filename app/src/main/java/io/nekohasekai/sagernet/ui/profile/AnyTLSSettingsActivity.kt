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
import io.nekohasekai.sagernet.fmt.anytls.AnyTLSBean
import io.nekohasekai.sagernet.ktx.applyDefaultValues

class AnyTLSSettingsActivity: ProfileSettingsActivity<AnyTLSBean>() {

    override fun createEntity() = AnyTLSBean().applyDefaultValues()

    override fun AnyTLSBean.init() {
        DataStore.profileName = name
        DataStore.serverAddress = serverAddress
        DataStore.serverPort = serverPort
        DataStore.serverPassword = password
        DataStore.serverSecurity = security
        DataStore.serverSNI = sni
        DataStore.serverALPN = alpn
        DataStore.serverCertificates = certificates
        DataStore.serverPinnedCertificateChain = pinnedPeerCertificateChainSha256
        DataStore.serverUTLSFingerprint = utlsFingerprint
        DataStore.serverEchConfig = echConfig
        //DataStore.serverEchDohServer = echDohServer
        DataStore.serverRealityPublicKey = realityPublicKey
        DataStore.serverRealityShortId = realityShortId
        DataStore.serverRealityFingerprint = realityFingerprint
        DataStore.serverAllowInsecure = allowInsecure
    }

    override fun AnyTLSBean.serialize() {
        name = DataStore.profileName
        serverAddress = DataStore.serverAddress
        serverPort = DataStore.serverPort
        password = DataStore.serverPassword
        security = DataStore.serverSecurity
        sni = DataStore.serverSNI
        alpn = DataStore.serverALPN
        certificates = DataStore.serverCertificates
        pinnedPeerCertificateChainSha256 = DataStore.serverPinnedCertificateChain
        utlsFingerprint = DataStore.serverUTLSFingerprint
        echConfig = DataStore.serverEchConfig
        //echDohServer = DataStore.serverEchDohServer
        realityPublicKey = DataStore.serverRealityPublicKey
        realityShortId = DataStore.serverRealityShortId
        realityFingerprint = DataStore.serverRealityFingerprint
        allowInsecure = DataStore.serverAllowInsecure
    }

    lateinit var password: EditTextPreference
    lateinit var security: SimpleMenuPreference
    lateinit var sni: EditTextPreference
    lateinit var alpn: EditTextPreference
    lateinit var securityCategory: PreferenceCategory
    lateinit var certificates: EditTextPreference
    lateinit var pinnedCertificateChain: EditTextPreference
    lateinit var allowInsecure: SwitchPreference
    lateinit var utlsFingerprint: SimpleMenuPreference
    lateinit var echConfig: EditTextPreference
    lateinit var echDohServer: EditTextPreference
    lateinit var realityPublicKey: EditTextPreference
    lateinit var realityShortId: EditTextPreference
    lateinit var realityFingerprint: SimpleMenuPreference

    override fun PreferenceFragmentCompat.createPreferences(
        savedInstanceState: Bundle?,
        rootKey: String?,
    ) {
        addPreferencesFromResource(R.xml.anytls_preferences)

        findPreference<EditTextPreference>(Key.SERVER_PORT)!!.apply {
            setOnBindEditTextListener(EditTextPreferenceModifiers.Port)
        }

        password = findPreference(Key.SERVER_PASSWORD)!!
        security = findPreference(Key.SERVER_SECURITY)!!
        sni = findPreference(Key.SERVER_SNI)!!
        alpn = findPreference(Key.SERVER_ALPN)!!
        securityCategory = findPreference(Key.SERVER_SECURITY_CATEGORY)!!
        certificates = findPreference(Key.SERVER_CERTIFICATES)!!
        pinnedCertificateChain = findPreference(Key.SERVER_PINNED_CERTIFICATE_CHAIN)!!
        allowInsecure = findPreference(Key.SERVER_ALLOW_INSECURE)!!
        utlsFingerprint = findPreference(Key.SERVER_UTLS_FINGERPRINT)!!
        echConfig = findPreference(Key.SERVER_ECH_CONFIG)!!
        //echDohServer = findPreference(Key.SERVER_ECH_DOH_SERVER)!!
        realityPublicKey = findPreference(Key.SERVER_REALITY_PUBLIC_KEY)!!
        realityShortId = findPreference(Key.SERVER_REALITY_SHORT_ID)!!
        realityFingerprint = findPreference(Key.SERVER_REALITY_FINGERPRINT)!!
        password.apply {
            summaryProvider = PasswordSummaryProvider
        }
        realityPublicKey.apply {
            summaryProvider = PasswordSummaryProvider
        }

        val tlev = resources.getStringArray(R.array.transport_layer_encryption_value)
        if (security.value !in tlev) {
                security.value = tlev[1]
        }
        updateTle(security.value)
        security.setOnPreferenceChangeListener { _, newValue ->
            updateTle(newValue as String)
            true
        }
    }

    fun updateTle(security: String) {
        securityCategory.isVisible = security == "tls" || security == "reality"
        certificates.isVisible = security == "tls"
        pinnedCertificateChain.isVisible = security == "tls"
        allowInsecure.isVisible = security == "tls"
        sni.isVisible = security == "tls" || security == "reality"
        alpn.isVisible = security == "tls"
        realityPublicKey.isVisible = security == "reality"
        realityShortId.isVisible = security == "reality"
        utlsFingerprint.isVisible = security == "tls"
        echConfig.isVisible = security == "tls"
        //echDohServer.isVisible = security == "tls"
        realityFingerprint.isVisible = security == "reality"
    }

}
