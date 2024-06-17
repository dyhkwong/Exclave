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

import android.app.Activity
import android.content.BroadcastReceiver
import android.content.DialogInterface
import android.os.Bundle
import android.view.View
import androidx.activity.result.component1
import androidx.activity.result.component2
import androidx.activity.result.contract.ActivityResultContracts
import androidx.fragment.app.setFragmentResultListener
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.whenCreated
import androidx.preference.EditTextPreference
import androidx.preference.Preference
import androidx.preference.PreferenceCategory
import androidx.preference.SwitchPreference
import com.github.shadowsocks.plugin.*
import com.github.shadowsocks.plugin.fragment.AlertDialogFragment
import com.github.shadowsocks.preference.PluginConfigurationDialogFragment
import com.github.shadowsocks.preference.PluginPreference
import com.github.shadowsocks.preference.PluginPreferenceDialogFragment
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.google.android.material.snackbar.Snackbar
import com.takisoft.preferencex.PreferenceFragmentCompat
import com.takisoft.preferencex.SimpleMenuPreference
import io.nekohasekai.sagernet.Key
import io.nekohasekai.sagernet.R
import io.nekohasekai.sagernet.database.DataStore
import io.nekohasekai.sagernet.database.preference.EditTextPreferenceModifiers
import io.nekohasekai.sagernet.fmt.http.HttpBean
import io.nekohasekai.sagernet.fmt.shadowsocks.ShadowsocksBean
import io.nekohasekai.sagernet.fmt.socks.SOCKSBean
import io.nekohasekai.sagernet.fmt.trojan.TrojanBean
import io.nekohasekai.sagernet.fmt.v2ray.StandardV2RayBean
import io.nekohasekai.sagernet.fmt.v2ray.VLESSBean
import io.nekohasekai.sagernet.fmt.v2ray.VMessBean
import io.nekohasekai.sagernet.ktx.app
import io.nekohasekai.sagernet.ktx.listenForPackageChanges
import io.nekohasekai.sagernet.ktx.readableMessage
import io.nekohasekai.sagernet.ktx.runOnDefaultDispatcher
import io.nekohasekai.sagernet.ktx.showAllowingStateLoss
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch

abstract class StandardV2RaySettingsActivity : ProfileSettingsActivity<StandardV2RayBean>(),
    Preference.OnPreferenceChangeListener {

    var bean: StandardV2RayBean? = null

    override fun StandardV2RayBean.init() {
        bean = this

        DataStore.profileName = name
        DataStore.serverAddress = serverAddress
        DataStore.serverPort = serverPort
        when (this) {
            is TrojanBean -> DataStore.serverUserId = password
            is ShadowsocksBean -> {
                DataStore.serverEncryption = method
                DataStore.serverUserId = password
            }
            is VMessBean, is VLESSBean -> {
                DataStore.serverUserId = uuid
                DataStore.serverEncryption = encryption
            }
            is HttpBean -> {
                DataStore.serverUserId = password
                DataStore.serverUsername = username
            }
            is SOCKSBean -> {
                DataStore.serverUserId = password
                DataStore.serverUsername = username
            }
        }
        DataStore.serverNetwork = type
        DataStore.serverHeader = headerType
        DataStore.serverHost = host

        when (type) {
            "kcp" -> DataStore.serverPath = mKcpSeed
            "quic" -> DataStore.serverPath = quicKey
            "grpc" -> DataStore.serverPath = grpcServiceName
            "meek" -> DataStore.serverPath = meekUrl
            else -> DataStore.serverPath = path
        }

        DataStore.serverSecurity = security
        DataStore.serverSNI = sni
        DataStore.serverALPN = alpn
        DataStore.serverCertificates = certificates
        when (this) {
            is VLESSBean -> DataStore.serverFlow = flow
            is VMessBean -> {
                DataStore.serverAlterId = alterId
                DataStore.serverVMessExperimentalAuthenticatedLength = experimentalAuthenticatedLength
                DataStore.serverVMessExperimentalNoTerminationSignal = experimentalNoTerminationSignal
            }
            is ShadowsocksBean -> {
                DataStore.serverPlugin = plugin
                DataStore.serverReducedIvHeadEntropy = experimentReducedIvHeadEntropy
            }
            is SOCKSBean -> {
                DataStore.serverProtocolVersion  = protocol

            }
        }
        DataStore.serverPinnedCertificateChain = pinnedPeerCertificateChainSha256
        DataStore.serverQuicSecurity = quicSecurity
        DataStore.serverWsMaxEarlyData = wsMaxEarlyData
        DataStore.serverEarlyDataHeaderName = earlyDataHeaderName
        DataStore.serverUTLSFingerprint = utlsFingerprint

        DataStore.serverRealityPublicKey = realityPublicKey
        DataStore.serverRealityShortId = realityShortId
        DataStore.serverRealitySpiderX = realitySpiderX
        DataStore.serverRealityFingerprint = realityFingerprint

        DataStore.serverUploadSpeed = hy2UpMbps
        DataStore.serverDownloadSpeed = hy2DownMbps
        DataStore.serverPassword = hy2Password
        DataStore.serverObfs = hy2ObfsPassword

        DataStore.serverWsBrowserForwarding = wsUseBrowserForwarder
        DataStore.serverAllowInsecure = allowInsecure
        DataStore.serverPacketEncoding = packetEncoding

    }

    override fun StandardV2RayBean.serialize() {
        name = DataStore.profileName
        serverAddress = DataStore.serverAddress
        serverPort = DataStore.serverPort
        when (this) {
            is TrojanBean -> {
                password = DataStore.serverUserId
            }
            is ShadowsocksBean -> {
                method = DataStore.serverEncryption
                password = DataStore.serverUserId
            }
            is VMessBean, is VLESSBean -> {
                uuid = DataStore.serverUserId
                encryption = DataStore.serverEncryption
            }
            is HttpBean -> {
                password = DataStore.serverUserId
                username = DataStore.serverUsername
            }
            is SOCKSBean -> {
                password = DataStore.serverUserId
                username = DataStore.serverUsername
            }
        }
        type = DataStore.serverNetwork
        headerType = DataStore.serverHeader
        host = DataStore.serverHost
        when (type) {
            "kcp" -> mKcpSeed = DataStore.serverPath
            "quic" -> quicKey = DataStore.serverPath
            "grpc" -> grpcServiceName = DataStore.serverPath
            "meek" -> meekUrl = DataStore.serverPath
            else -> path = DataStore.serverPath
        }
        security = DataStore.serverSecurity
        sni = DataStore.serverSNI
        alpn = DataStore.serverALPN
        certificates = DataStore.serverCertificates
        pinnedPeerCertificateChainSha256 = DataStore.serverPinnedCertificateChain
        when (this) {
            is VLESSBean -> flow = DataStore.serverFlow
            is VMessBean -> {
                alterId = DataStore.serverAlterId
                experimentalAuthenticatedLength = DataStore.serverVMessExperimentalAuthenticatedLength
                experimentalNoTerminationSignal = DataStore.serverVMessExperimentalNoTerminationSignal
            }
            is ShadowsocksBean -> {
                plugin = DataStore.serverPlugin
                experimentReducedIvHeadEntropy = DataStore.serverReducedIvHeadEntropy
            }
            is SOCKSBean -> protocol = DataStore.serverProtocolVersion
        }
        quicSecurity = DataStore.serverQuicSecurity
        wsMaxEarlyData = DataStore.serverWsMaxEarlyData
        earlyDataHeaderName = DataStore.serverEarlyDataHeaderName
        utlsFingerprint = DataStore.serverUTLSFingerprint

        realityPublicKey = DataStore.serverRealityPublicKey
        realityShortId = DataStore.serverRealityShortId
        realitySpiderX = DataStore.serverRealitySpiderX
        realityFingerprint = DataStore.serverRealityFingerprint

        hy2UpMbps = DataStore.serverUploadSpeed
        hy2DownMbps = DataStore.serverDownloadSpeed
        hy2Password = DataStore.serverPassword
        hy2ObfsPassword = DataStore.serverObfs

        wsUseBrowserForwarder = DataStore.serverWsBrowserForwarding
        allowInsecure = DataStore.serverAllowInsecure
        packetEncoding = DataStore.serverPacketEncoding
    }

    lateinit var encryption: SimpleMenuPreference
    lateinit var network: SimpleMenuPreference
    lateinit var header: SimpleMenuPreference
    lateinit var requestHost: EditTextPreference
    lateinit var path: EditTextPreference
    lateinit var quicSecurity: SimpleMenuPreference
    lateinit var security: SimpleMenuPreference
    lateinit var xtlsFlow: SimpleMenuPreference
    lateinit var alterId: EditTextPreference

    lateinit var sni: EditTextPreference
    lateinit var alpn: EditTextPreference
    lateinit var securityCategory: PreferenceCategory
    lateinit var certificates: EditTextPreference
    lateinit var pinnedCertificateChain: EditTextPreference
    lateinit var allowInsecure: SwitchPreference
    lateinit var utlsFingerprint: SimpleMenuPreference

    lateinit var realityPublicKey: EditTextPreference
    lateinit var realityShortId: EditTextPreference
    lateinit var realitySpiderX: EditTextPreference
    lateinit var realityFingerprint: SimpleMenuPreference

    lateinit var packetEncoding: SimpleMenuPreference

    lateinit var hy2UpMbps: EditTextPreference
    lateinit var hy2DownMbps: EditTextPreference
    lateinit var hy2Password: EditTextPreference
    lateinit var hy2ObfsPassword: EditTextPreference

    lateinit var socksProtocol: SimpleMenuPreference
    lateinit var passwordUUID: EditTextPreference

    lateinit var wsCategory: PreferenceCategory
    lateinit var ssExperimentsCategory: PreferenceCategory

    lateinit var plugin: PluginPreference
    lateinit var pluginConfigure: EditTextPreference
    lateinit var pluginConfiguration: PluginConfiguration
    lateinit var receiver: BroadcastReceiver

    override fun PreferenceFragmentCompat.createPreferences(
        savedInstanceState: Bundle?,
        rootKey: String?,
    ) {
        addPreferencesFromResource(R.xml.standard_v2ray_preferences)

        findPreference<EditTextPreference>(Key.SERVER_PORT)!!.apply {
            setOnBindEditTextListener(EditTextPreferenceModifiers.Port)
        }

        encryption = findPreference(Key.SERVER_ENCRYPTION)!!
        network = findPreference(Key.SERVER_NETWORK)!!
        header = findPreference(Key.SERVER_HEADER)!!
        requestHost = findPreference(Key.SERVER_HOST)!!
        path = findPreference(Key.SERVER_PATH)!!
        quicSecurity = findPreference(Key.SERVER_QUIC_SECURITY)!!
        security = findPreference(Key.SERVER_SECURITY)!!

        sni = findPreference(Key.SERVER_SNI)!!
        alpn = findPreference(Key.SERVER_ALPN)!!
        securityCategory = findPreference(Key.SERVER_SECURITY_CATEGORY)!!
        certificates = findPreference(Key.SERVER_CERTIFICATES)!!
        pinnedCertificateChain = findPreference(Key.SERVER_PINNED_CERTIFICATE_CHAIN)!!
        allowInsecure = findPreference(Key.SERVER_ALLOW_INSECURE)!!
        xtlsFlow = findPreference(Key.SERVER_FLOW)!!
        alterId = findPreference(Key.SERVER_ALTER_ID)!!
        utlsFingerprint = findPreference(Key.SERVER_UTLS_FINGERPRINT)!!

        realityPublicKey = findPreference(Key.SERVER_REALITY_PUBLIC_KEY)!!
        realityShortId = findPreference(Key.SERVER_REALITY_SHORT_ID)!!
        realitySpiderX = findPreference(Key.SERVER_REALITY_SPIDER_X)!!
        realityFingerprint = findPreference(Key.SERVER_REALITY_FINGERPRINT)!!

        hy2UpMbps = findPreference(Key.SERVER_UPLOAD_SPEED)!!
        hy2UpMbps.apply {
            setOnBindEditTextListener(EditTextPreferenceModifiers.Number)
        }
        hy2DownMbps = findPreference(Key.SERVER_DOWNLOAD_SPEED)!!
        hy2DownMbps.apply {
            setOnBindEditTextListener(EditTextPreferenceModifiers.Number)
        }
        hy2Password = findPreference(Key.SERVER_PASSWORD)!!
        hy2Password.apply {
            summaryProvider = PasswordSummaryProvider
            title = resources.getString(R.string.hysteria2_password)
        }
        hy2ObfsPassword = findPreference(Key.SERVER_OBFS)!!
        hy2ObfsPassword.apply {
            summaryProvider = PasswordSummaryProvider
        }

        wsCategory = findPreference(Key.SERVER_WS_CATEGORY)!!

        when (bean) {
            is VLESSBean -> {
                encryption.setEntries(R.array.vless_encryption_entry)
                encryption.setEntryValues(R.array.vless_encryption_value)
                val vev = resources.getStringArray(R.array.vless_encryption_value)
                if (encryption.value !in vev) {
                    encryption.value = vev[0]
                }
                val xfv = resources.getStringArray(R.array.xtls_flow_value)
                if (xtlsFlow.value !in xfv) {
                    xtlsFlow.value = xfv[0]
                }
            }
            is VMessBean -> {
                encryption.setEntries(R.array.vmess_encryption_entry)
                encryption.setEntryValues(R.array.vmess_encryption_value)
                val vev = resources.getStringArray(R.array.vmess_encryption_value)
                if (encryption.value !in vev) {
                    encryption.value = "auto"
                }
            }
            is ShadowsocksBean -> {
                encryption.setEntries(R.array.enc_method_entry)
                encryption.setEntryValues(R.array.enc_method_value)
                val sev = resources.getStringArray(R.array.enc_method_value)
                if (encryption.value !in sev) {
                    encryption.value = "aes-256-gcm"
                }
            }
            else -> {
                encryption.isVisible = false
            }
        }

        passwordUUID = findPreference(Key.SERVER_USER_ID)!!
        passwordUUID.apply {
            summaryProvider = PasswordSummaryProvider
            if (bean is TrojanBean || bean is ShadowsocksBean || bean is SOCKSBean || bean is HttpBean) {
                title = resources.getString(R.string.password)
                dialogTitle = resources.getString(R.string.password)
            }
        }

        alterId.isVisible = bean is VMessBean
        alterId.setOnBindEditTextListener(EditTextPreferenceModifiers.Port)

        updateView(network.value)
        network.setOnPreferenceChangeListener { _, newValue ->
            updateView(newValue as String)
            true
        }

        security.setOnPreferenceChangeListener { _, newValue ->
            updateTle(newValue as String)
            true
        }

        findPreference<PreferenceCategory>(Key.SERVER_VMESS_EXPERIMENTS_CATEGORY)!!.isVisible = bean is VMessBean
        xtlsFlow.isVisible = bean is VLESSBean
        findPreference<SimpleMenuPreference>(Key.SERVER_PACKET_ENCODING)!!.isVisible = bean is VMessBean || bean is VLESSBean
        findPreference<PreferenceCategory>(Key.SERVER_PLUGIN_CATEGORY)!!.isVisible = bean is ShadowsocksBean
        
        packetEncoding = findPreference(Key.SERVER_PACKET_ENCODING)!!
        packetEncoding.isVisible = bean is VMessBean || bean is VLESSBean
        val pev = resources.getStringArray(R.array.packet_encoding_value)
        if (packetEncoding.value !in pev) {
            packetEncoding.value = pev[0]
        }

        ssExperimentsCategory = findPreference(Key.SERVER_SS_EXPERIMENTS_CATEGORY)!!
        fun updateMethod(method: String) {
            ssExperimentsCategory.isVisible = bean is ShadowsocksBean && !method.startsWith("2022-blake3-")
        }
        updateMethod(DataStore.serverEncryption)
        encryption.setOnPreferenceChangeListener { _, newValue ->
            updateMethod(newValue as String)
            true
        }

        socksProtocol = findPreference(Key.SERVER_PROTOCOL)!!
        socksProtocol.isVisible = bean is SOCKSBean
        fun updateProtocol(version: Int) {
            passwordUUID.isVisible = version == SOCKSBean.PROTOCOL_SOCKS5
        }
        if (bean is SOCKSBean) {
            updateProtocol(DataStore.serverProtocolVersion)
        }
        socksProtocol.setOnPreferenceChangeListener { _, newValue ->
            updateProtocol((newValue as String).toInt())
            true
        }

        findPreference<EditTextPreference>(Key.SERVER_USERNAME)!!.isVisible = bean is SOCKSBean || bean is HttpBean

        plugin = findPreference(Key.SERVER_PLUGIN)!!
        pluginConfigure = findPreference(Key.SERVER_PLUGIN_CONFIGURE)!!
        pluginConfigure.setOnBindEditTextListener(EditTextPreferenceModifiers.Monospace)
        pluginConfigure.onPreferenceChangeListener = this@StandardV2RaySettingsActivity
        pluginConfiguration = PluginConfiguration(DataStore.serverPlugin)
        initPlugins()
    }

    val tcpHeadersValue = app.resources.getStringArray(R.array.tcp_headers_value)
    val kcpQuicHeadersValue = app.resources.getStringArray(R.array.kcp_quic_headers_value)
    val quicSecurityValue = app.resources.getStringArray(R.array.quic_security_value)

    fun updateView(network: String) {
        security.setEntries(R.array.transport_layer_encryption_entry)
        security.setEntryValues(R.array.transport_layer_encryption_value)
        security.value = DataStore.serverSecurity

        val tlev = resources.getStringArray(R.array.transport_layer_encryption_value)
        if (security.value !in tlev) {
            security.value = tlev[0]
        }

        updateTle(security.value)

        val isTCP = network == "tcp"
        val isQUIC = network == "quic"
        val isWS = network == "ws"
        val isHTTP = network == "http"
        val isMeek = network == "meek"
        val isHTTPUpgrade = network == "httpupgrade"
        val isGRPC = network == "grpc"
        val isSplitHTTP = network == "splithttp"
        val isHysteria2 = network == "hysteria2"
        hy2UpMbps.isVisible = isHysteria2
        hy2DownMbps.isVisible = isHysteria2
        hy2Password.isVisible = isHysteria2
        hy2ObfsPassword.isVisible = isHysteria2
        quicSecurity.isVisible = isQUIC
        utlsFingerprint.isVisible = security.value == "tls" && (isTCP || isWS || isHTTP || isMeek || isHTTPUpgrade || isGRPC || isSplitHTTP)
        realityFingerprint.isVisible = security.value == "reality"
        if (isQUIC) {
            if (DataStore.serverQuicSecurity !in quicSecurityValue) {
                quicSecurity.value = quicSecurityValue[0]
            } else {
                quicSecurity.value = DataStore.serverQuicSecurity
            }
        }

        wsCategory.isVisible = isWS

        when (network) {
            "tcp" -> {
                header.setEntries(R.array.tcp_headers_entry)
                header.setEntryValues(R.array.tcp_headers_value)

                if (DataStore.serverHeader !in tcpHeadersValue) {
                    header.value = tcpHeadersValue[0]
                } else {
                    header.value = DataStore.serverHeader
                }

                var isHttp = header.value == "http"
                requestHost.isVisible = isHttp
                path.isVisible = isHttp

                header.setOnPreferenceChangeListener { _, newValue ->
                    isHttp = newValue == "http"
                    requestHost.isVisible = isHttp
                    path.isVisible = isHttp
                    true
                }

                requestHost.setTitle(R.string.http_host)
                path.setTitle(R.string.http_path)

                header.isVisible = true
            }
            "http", "httpupgrade", "splithttp" -> {
                requestHost.setTitle(R.string.http_host)
                path.setTitle(R.string.http_path)

                header.isVisible = false
                requestHost.isVisible = true
                path.isVisible = true
            }
            "ws" -> {
                requestHost.setTitle(R.string.ws_host)
                path.setTitle(R.string.ws_path)

                header.isVisible = false
                requestHost.isVisible = true
                path.isVisible = true
            }
            "kcp" -> {
                header.setEntries(R.array.kcp_quic_headers_entry)
                header.setEntryValues(R.array.kcp_quic_headers_value)
                path.setTitle(R.string.kcp_seed)

                if (DataStore.serverHeader !in kcpQuicHeadersValue) {
                    header.value = kcpQuicHeadersValue[0]
                } else {
                    header.value = DataStore.serverHeader
                }

                header.onPreferenceChangeListener = null

                header.isVisible = true
                requestHost.isVisible = false
                path.isVisible = true
            }
            "quic" -> {
                header.setEntries(R.array.kcp_quic_headers_entry)
                header.setEntryValues(R.array.kcp_quic_headers_value)
                path.setTitle(R.string.quic_key)

                if (DataStore.serverHeader !in kcpQuicHeadersValue) {
                    header.value = kcpQuicHeadersValue[0]
                } else {
                    header.value = DataStore.serverHeader
                }

                header.onPreferenceChangeListener = null

                header.isVisible = true
                requestHost.isVisible = false
                path.isVisible = true
            }
            "grpc" -> {
                path.setTitle(R.string.grpc_service_name)

                header.isVisible = false
                requestHost.isVisible = false
                path.isVisible = true
            }
            "meek" -> {
                path.setTitle(R.string.meek_url)

                header.isVisible = false
                requestHost.isVisible = false
                path.isVisible = true
            }
            "hysteria2" -> {
                path.isVisible = false
                header.isVisible = false
                requestHost.isVisible = false
            }
        }
    }

    fun updateTle(tle: String) {
        val isTLS = tle == "tls"
        val isReality = tle == "reality"
        securityCategory.isVisible = isTLS || isReality
        certificates.isVisible = isTLS
        pinnedCertificateChain.isVisible = isTLS
        allowInsecure.isVisible = isTLS
        sni.isVisible = isTLS || isReality
        alpn.isVisible = isTLS
        realityPublicKey.isVisible = isReality
        realityShortId.isVisible = isReality
        realitySpiderX.isVisible = isReality
        utlsFingerprint.isVisible = isTLS && (network.value == "tcp" || network.value == "ws"
                || network.value == "http" || network.value == "meek" || network.value == "httpupgrade"
                || network.value == "grpc" || network.value == "splithttp")
        realityFingerprint.isVisible = isReality
    }

    override fun onAttachedToWindow() {
        super.onAttachedToWindow()

        receiver = listenForPackageChanges(false) {
            lifecycleScope.launch(Dispatchers.Main) {   // wait until changes were flushed
                whenCreated { initPlugins() }
            }
        }
    }
    override fun PreferenceFragmentCompat.viewCreated(view: View, savedInstanceState: Bundle?) {
        setFragmentResultListener(PluginPreferenceDialogFragment::class.java.name) { _, bundle ->
            val selected = plugin.plugins.lookup.getValue(
                bundle.getString(PluginPreferenceDialogFragment.KEY_SELECTED_ID)!!
            )
            val override = pluginConfiguration.pluginsOptions.keys.firstOrNull {
                plugin.plugins.lookup[it] == selected
            }
            pluginConfiguration = PluginConfiguration(
                pluginConfiguration.pluginsOptions, override ?: selected.id
            )
            DataStore.serverPlugin = pluginConfiguration.toString()
            DataStore.dirty = true
            plugin.value = pluginConfiguration.selected
            pluginConfigure.isEnabled = selected !is NoPlugin
            pluginConfigure.text = pluginConfiguration.getOptions().toString()
            if (!selected.trusted) {
                Snackbar.make(requireView(), R.string.plugin_untrusted, Snackbar.LENGTH_LONG).show()
            }
        }
        AlertDialogFragment.setResultListener<Empty>(
            this, UnsavedChangesDialogFragment::class.java.simpleName
        ) { which, _ ->
            when (which) {
                DialogInterface.BUTTON_POSITIVE -> {
                    runOnDefaultDispatcher {
                        saveAndExit()
                    }
                }
                DialogInterface.BUTTON_NEGATIVE -> requireActivity().finish()
            }
        }
    }

    private fun initPlugins() {
        plugin.value = pluginConfiguration.selected
        plugin.init()
        pluginConfigure.isEnabled = plugin.selectedEntry?.let { it is NoPlugin } == false
        pluginConfigure.text = pluginConfiguration.getOptions().toString()
    }

    private fun showPluginEditor() {
        PluginConfigurationDialogFragment().apply {
            setArg(Key.SERVER_PLUGIN_CONFIGURE, pluginConfiguration.selected)
            setTargetFragment(child, 0)
        }.showAllowingStateLoss(supportFragmentManager, Key.SERVER_PLUGIN_CONFIGURE)
    }

     override fun onPreferenceChange(preference: Preference, newValue: Any?): Boolean = try {
        val selected = pluginConfiguration.selected
        pluginConfiguration = PluginConfiguration(
            (pluginConfiguration.pluginsOptions + (pluginConfiguration.selected to PluginOptions(
                selected, newValue as? String?
            ))).toMutableMap(), selected
        )
        DataStore.serverPlugin = pluginConfiguration.toString()
        DataStore.dirty = true
        true
    } catch (exc: RuntimeException) {
        Snackbar.make(child.requireView(), exc.readableMessage, Snackbar.LENGTH_LONG).show()
        false
    }

    private val configurePlugin = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { (resultCode, data) ->
        when (resultCode) {
            Activity.RESULT_OK -> {
                val options = data?.getStringExtra(PluginContract.EXTRA_OPTIONS)
                pluginConfigure.text = options
                onPreferenceChange(pluginConfigure, options)
            }
            PluginContract.RESULT_FALLBACK -> showPluginEditor()
        }
    }

    override fun PreferenceFragmentCompat.displayPreferenceDialog(preference: Preference): Boolean {
        when (preference.key) {
            Key.SERVER_PLUGIN -> PluginPreferenceDialogFragment().apply {
                setArg(Key.SERVER_PLUGIN)
                setTargetFragment(child, 0)
            }.showAllowingStateLoss(supportFragmentManager, Key.SERVER_PLUGIN)
            Key.SERVER_PLUGIN_CONFIGURE -> {
                val intent = PluginManager.buildIntent(
                    plugin.selectedEntry!!.id, PluginContract.ACTION_CONFIGURE
                )
                if (intent.resolveActivity(packageManager) == null) showPluginEditor() else {
                    configurePlugin.launch(
                        intent.putExtra(
                            PluginContract.EXTRA_OPTIONS,
                            pluginConfiguration.getOptions().toString()
                        )
                    )
                }
            }
            else -> return false
        }
        return true
    }

    val pluginHelp = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { (resultCode, data) ->
        if (resultCode == Activity.RESULT_OK) MaterialAlertDialogBuilder(this).setTitle("?")
            .setMessage(data?.getCharSequenceExtra(PluginContract.EXTRA_HELP_MESSAGE))
            .show()
    }

}
