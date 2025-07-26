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
import io.nekohasekai.sagernet.ktx.unwrapIDN

class AnyTLSSettingsActivity: ProfileSettingsActivity<AnyTLSBean>() {

    override fun createEntity() = AnyTLSBean()

    override fun AnyTLSBean.init() {
        DataStore.profileName = name
        DataStore.serverAddress = serverAddress
        DataStore.serverPort = serverPort
        DataStore.serverPassword = password
        DataStore.serverAnyTLSIdleSessionCheckInterval = idleSessionCheckInterval
        DataStore.serverAnyTLSIdleSessionTimeout = idleSessionTimeout
        DataStore.serverAnyTLSMinIdleSession = minIdleSession
        DataStore.serverSecurity = security
        DataStore.serverSNI = sni
        DataStore.serverALPN = alpn
        DataStore.serverCertificates = certificates
        DataStore.serverPinnedCertificateChain = pinnedPeerCertificateChainSha256
        DataStore.serverUTLSFingerprint = utlsFingerprint
        DataStore.serverEchConfig = echConfig
        DataStore.serverRealityPublicKey = realityPublicKey
        DataStore.serverRealityShortId = realityShortId
        DataStore.serverRealityFingerprint = realityFingerprint
        DataStore.serverRealityDisableX25519Mlkem768 = realityDisableX25519Mlkem768
        DataStore.serverAllowInsecure = allowInsecure
    }

    override fun AnyTLSBean.serialize() {
        name = DataStore.profileName
        serverAddress = DataStore.serverAddress.unwrapIDN()
        serverPort = DataStore.serverPort
        password = DataStore.serverPassword
        idleSessionCheckInterval = DataStore.serverAnyTLSIdleSessionCheckInterval
        idleSessionTimeout = DataStore.serverAnyTLSIdleSessionTimeout
        minIdleSession = DataStore.serverAnyTLSMinIdleSession
        security = DataStore.serverSecurity
        sni = DataStore.serverSNI
        alpn = DataStore.serverALPN
        certificates = DataStore.serverCertificates
        pinnedPeerCertificateChainSha256 = DataStore.serverPinnedCertificateChain
        utlsFingerprint = DataStore.serverUTLSFingerprint
        echConfig = DataStore.serverEchConfig
        realityPublicKey = DataStore.serverRealityPublicKey
        realityShortId = DataStore.serverRealityShortId
        realityFingerprint = DataStore.serverRealityFingerprint
        realityDisableX25519Mlkem768 = DataStore.serverRealityDisableX25519Mlkem768
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
    lateinit var realityPublicKey: EditTextPreference
    lateinit var realityShortId: EditTextPreference
    lateinit var realityFingerprint: SimpleMenuPreference
    lateinit var realityDisableX25519Mlkem768: SwitchPreference

    override fun PreferenceFragmentCompat.createPreferences(
        savedInstanceState: Bundle?,
        rootKey: String?,
    ) {
        addPreferencesFromResource(R.xml.anytls_preferences)

        findPreference<EditTextPreference>(Key.SERVER_PORT)!!.apply {
            setOnBindEditTextListener(EditTextPreferenceModifiers.Port)
        }

        password = findPreference(Key.SERVER_PASSWORD)!!
        findPreference<EditTextPreference>(Key.SERVER_ANYTLS_IDLE_SESSION_CHECK_INTERVAL)!!.apply {
            setOnBindEditTextListener(EditTextPreferenceModifiers.Number)
        }
        findPreference<EditTextPreference>(Key.SERVER_ANYTLS_IDLE_SESSION_TIMEOUT)!!.apply {
            setOnBindEditTextListener(EditTextPreferenceModifiers.Number)
        }
        findPreference<EditTextPreference>(Key.SERVER_ANYTLS_MIN_IDLE_SESSION)!!.apply {
            setOnBindEditTextListener(EditTextPreferenceModifiers.Number)
        }
        security = findPreference(Key.SERVER_SECURITY)!!
        sni = findPreference(Key.SERVER_SNI)!!
        alpn = findPreference(Key.SERVER_ALPN)!!
        securityCategory = findPreference(Key.SERVER_SECURITY_CATEGORY)!!
        certificates = findPreference(Key.SERVER_CERTIFICATES)!!
        pinnedCertificateChain = findPreference(Key.SERVER_PINNED_CERTIFICATE_CHAIN)!!
        allowInsecure = findPreference(Key.SERVER_ALLOW_INSECURE)!!
        utlsFingerprint = findPreference(Key.SERVER_UTLS_FINGERPRINT)!!
        echConfig = findPreference(Key.SERVER_ECH_CONFIG)!!
        realityPublicKey = findPreference(Key.SERVER_REALITY_PUBLIC_KEY)!!
        realityShortId = findPreference(Key.SERVER_REALITY_SHORT_ID)!!
        realityFingerprint = findPreference(Key.SERVER_REALITY_FINGERPRINT)!!
        realityDisableX25519Mlkem768 = findPreference(Key.SERVER_REALITY_DISABLE_X25519MLKEM768)!!
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
        echConfig.isVisible = security == "tls"
        realityPublicKey.isVisible = security == "reality"
        realityShortId.isVisible = security == "reality"
        utlsFingerprint.isVisible = security == "tls"
        realityFingerprint.isVisible = security == "reality"
        realityDisableX25519Mlkem768.isVisible = security == "reality"
    }

}
