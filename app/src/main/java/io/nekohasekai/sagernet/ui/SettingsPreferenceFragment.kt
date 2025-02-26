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

package io.nekohasekai.sagernet.ui

import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.view.View
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.view.updatePadding
import androidx.preference.EditTextPreference
import androidx.preference.Preference
import androidx.preference.SwitchPreference
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.takisoft.preferencex.PreferenceFragmentCompat
import com.takisoft.preferencex.SimpleMenuPreference
import io.nekohasekai.sagernet.*
import io.nekohasekai.sagernet.database.DataStore
import io.nekohasekai.sagernet.database.preference.EditTextPreferenceModifiers
import io.nekohasekai.sagernet.ktx.*
import io.nekohasekai.sagernet.utils.Theme
import io.nekohasekai.sagernet.widget.ColorPickerPreference
import io.nekohasekai.sagernet.widget.LinkOrContentPreference
import kotlinx.coroutines.delay
import libcore.Libcore
import java.io.File

class SettingsPreferenceFragment : PreferenceFragmentCompat() {

    private lateinit var isProxyApps: SwitchPreference

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        listView.layoutManager = FixedLinearLayoutManager(listView)
        ViewCompat.setOnApplyWindowInsetsListener(listView) { v, insets ->
            val bars = insets.getInsets(
                WindowInsetsCompat.Type.systemBars()
                        or WindowInsetsCompat.Type.displayCutout()
            )
            v.updatePadding(
                left = bars.left,
                right = bars.right,
                bottom = bars.bottom,
            )
            WindowInsetsCompat.CONSUMED
        }
    }

    val reloadListener = Preference.OnPreferenceChangeListener { _, _ ->
        needReload()
        true
    }

    override fun onCreatePreferencesFix(savedInstanceState: Bundle?, rootKey: String?) {
        preferenceManager.preferenceDataStore = DataStore.configurationStore
        DataStore.initGlobal()
        addPreferencesFromResource(R.xml.global_preferences)
        val appTheme = findPreference<ColorPickerPreference>(Key.APP_THEME)!!
        appTheme.setOnPreferenceChangeListener { _, newTheme ->
            if (SagerNet.started) {
                SagerNet.reloadService()
            }
            val theme = Theme.getTheme(newTheme as Int)
            app.setTheme(theme)
            requireActivity().apply {
                // FIXME
                this.finish()
                startActivity(intent)
            }
            true
        }
        val nightTheme = findPreference<SimpleMenuPreference>(Key.NIGHT_THEME)!!
        nightTheme.setOnPreferenceChangeListener { _, newTheme ->
            Theme.currentNightMode = (newTheme as String).toInt()
            Theme.applyNightTheme()
            requireActivity().apply {
                // FIXME
                this.finish()
                startActivity(intent)
            }
            true
        }
        val portSocks5 = findPreference<EditTextPreference>(Key.SOCKS_PORT)!!
        val speedInterval = findPreference<Preference>(Key.SPEED_INTERVAL)!!
        val serviceMode = findPreference<Preference>(Key.SERVICE_MODE)!!
        val allowAccess = findPreference<Preference>(Key.ALLOW_ACCESS)!!
        val requireHttp = findPreference<SwitchPreference>(Key.REQUIRE_HTTP)!!
        val appendHttpProxy = findPreference<SwitchPreference>(Key.APPEND_HTTP_PROXY)!!
        val httpProxyException = findPreference<EditTextPreference>(Key.HTTP_PROXY_EXCEPTION)!!
        val portHttp = findPreference<EditTextPreference>(Key.HTTP_PORT)!!

        portHttp.isEnabled = requireHttp.isChecked
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) {
            appendHttpProxy.remove()
            httpProxyException.remove()
            requireHttp.setOnPreferenceChangeListener { _, newValue ->
                portHttp.isEnabled = newValue as Boolean
                needReload()
                true
            }
        } else {
            appendHttpProxy.isEnabled = requireHttp.isChecked
            httpProxyException.isVisible = appendHttpProxy.isChecked
            httpProxyException.isEnabled = appendHttpProxy.isEnabled && appendHttpProxy.isChecked
            requireHttp.setOnPreferenceChangeListener { _, newValue ->
                portHttp.isEnabled = newValue as Boolean
                appendHttpProxy.isEnabled = newValue
                httpProxyException.isVisible = appendHttpProxy.isChecked
                httpProxyException.isEnabled = newValue && appendHttpProxy.isChecked
                needReload()
                true
            }
            appendHttpProxy.setOnPreferenceChangeListener { _, newValue ->
                httpProxyException.isVisible = newValue as Boolean
                httpProxyException.isEnabled = newValue
                needReload()
                true
            }
        }

        val portLocalDns = findPreference<EditTextPreference>(Key.LOCAL_DNS_PORT)!!
        val ipv6Mode = findPreference<Preference>(Key.IPV6_MODE)!!
        val domainStrategy = findPreference<Preference>(Key.DOMAIN_STRATEGY)!!

        val bypassLan = findPreference<SwitchPreference>(Key.BYPASS_LAN)!!
        val bypassLanInCoreOnly = findPreference<SwitchPreference>(Key.BYPASS_LAN_IN_CORE_ONLY)!!

        bypassLanInCoreOnly.isEnabled = bypassLan.isChecked
        bypassLan.setOnPreferenceChangeListener { _, newValue ->
            bypassLanInCoreOnly.isEnabled = newValue as Boolean
            needReload()
            true
        }

        val remoteDns = findPreference<EditTextPreference>(Key.REMOTE_DNS)!!
        val directDns = findPreference<EditTextPreference>(Key.DIRECT_DNS)!!
        val useLocalDnsAsDirectDns = findPreference<SwitchPreference>(Key.USE_LOCAL_DNS_AS_DIRECT_DNS)!!
        val bootstrapDns = findPreference<EditTextPreference>(Key.BOOTSTRAP_DNS)!!
        val useLocalDnsAsBootstrapDns = findPreference<SwitchPreference>(Key.USE_LOCAL_DNS_AS_BOOTSTRAP_DNS)!!
        val remoteDnsQueryStrategy = findPreference<SimpleMenuPreference>(Key.REMOTE_DNS_QUERY_STRATEGY)!!
        val directDnsQueryStrategy = findPreference<SimpleMenuPreference>(Key.DIRECT_DNS_QUERY_STRATEGY)!!
        val ednsClientIp = findPreference<EditTextPreference>(Key.EDNS_CLIENT_IP)!!

        directDns.isEnabled = !DataStore.useLocalDnsAsDirectDns
        useLocalDnsAsDirectDns.setOnPreferenceChangeListener { _, newValue ->
            directDns.isEnabled = newValue == false
            needReload()
            true
        }

        bootstrapDns.isEnabled = !DataStore.useLocalDnsAsBootstrapDns
        useLocalDnsAsBootstrapDns.setOnPreferenceChangeListener { _, newValue ->
            bootstrapDns.isEnabled = newValue == false
            needReload()
            true
        }

        val enableDnsRouting = findPreference<SwitchPreference>(Key.ENABLE_DNS_ROUTING)!!
        val enableFakeDns = findPreference<SwitchPreference>(Key.ENABLE_FAKEDNS)!!

        val requireTransproxy = findPreference<SwitchPreference>(Key.REQUIRE_TRANSPROXY)!!
        val transproxyPort = findPreference<EditTextPreference>(Key.TRANSPROXY_PORT)!!
        val transproxyMode = findPreference<SimpleMenuPreference>(Key.TRANSPROXY_MODE)!!
        val logLevel = findPreference<SimpleMenuPreference>(Key.LOG_LEVEL)!!

        findPreference<EditTextPreference>(Key.PPROF_SERVER)!!.apply {
            isVisible = DataStore.enableDebug
            onPreferenceChangeListener = reloadListener
        }

        transproxyPort.isEnabled = requireTransproxy.isChecked
        transproxyMode.isEnabled = requireTransproxy.isChecked

        requireTransproxy.setOnPreferenceChangeListener { _, newValue ->
            transproxyPort.isEnabled = newValue as Boolean
            transproxyMode.isEnabled = newValue
            needReload()
            true
        }

        val shadowsocks2022Implementation = findPreference<SimpleMenuPreference>(Key.SHADOWSOCKS_2022_IMPLEMENTATION)!!
        val providerHysteria2 = findPreference<SimpleMenuPreference>(Key.PROVIDER_HYSTERIA2)!!
        val hysteriaEnablePortHopping = findPreference<SwitchPreference>(Key.HYSTERIA_ENABLE_PORT_HOPPING)!!
        val dnsHosts = findPreference<EditTextPreference>(Key.DNS_HOSTS)!!

        portLocalDns.setOnBindEditTextListener(EditTextPreferenceModifiers.Port)
        portSocks5.setOnBindEditTextListener(EditTextPreferenceModifiers.Port)
        portHttp.setOnBindEditTextListener(EditTextPreferenceModifiers.Port)
        dnsHosts.setOnBindEditTextListener(EditTextPreferenceModifiers.Hosts)
        dnsHosts.dialogMessage = getString(R.string.one_per_line_format, "example.com 127.0.0.1\nwww.example.com 127.0.0.1 127.0.0.2")

        val metedNetwork = findPreference<Preference>(Key.METERED_NETWORK)!!
        if (Build.VERSION.SDK_INT < 28) {
            metedNetwork.remove()
        }
        isProxyApps = findPreference(Key.PROXY_APPS)!!
        isProxyApps.setOnPreferenceChangeListener { _, newValue ->
            startActivity(Intent(activity, AppManagerActivity::class.java))
            if (newValue as Boolean) DataStore.dirty = true
            newValue
        }

        val appTrafficStatistics = findPreference<SwitchPreference>(Key.APP_TRAFFIC_STATISTICS)!!
        val showDirectSpeed = findPreference<SwitchPreference>(Key.SHOW_DIRECT_SPEED)!!
        val profileTrafficStatistics = findPreference<SwitchPreference>(Key.PROFILE_TRAFFIC_STATISTICS)!!
        speedInterval.isEnabled = profileTrafficStatistics.isChecked
        profileTrafficStatistics.setOnPreferenceChangeListener { _, newValue ->
            newValue as Boolean
            speedInterval.isEnabled = newValue
            showDirectSpeed.isEnabled = newValue
            needReload()
            true
        }

        findPreference<SwitchPreference>(Key.SHOW_GROUP_NAME)!!.onPreferenceChangeListener = reloadListener

        serviceMode.setOnPreferenceChangeListener { _, _ ->
            if (SagerNet.started) {
                SagerNet.stopService()
                runOnMainDispatcher {
                    delay(300)
                    SagerNet.startService()
                }
            }

            true
        }

        val tunImplementation = findPreference<SimpleMenuPreference>(Key.TUN_IMPLEMENTATION)!!
        val trafficSniffing = findPreference<SwitchPreference>(Key.TRAFFIC_SNIFFING)!!
        val destinationOverride = findPreference<SwitchPreference>(Key.DESTINATION_OVERRIDE)!!
        val hijackDns = findPreference<SwitchPreference>(Key.HIJACK_DNS)!!
        destinationOverride.isEnabled = trafficSniffing.isChecked
        hijackDns.isEnabled = trafficSniffing.isChecked
        trafficSniffing.setOnPreferenceChangeListener { _, newValue ->
            destinationOverride.isEnabled = newValue as Boolean
            hijackDns.isEnabled = newValue
            needReload()
            true
        }
        val resolveDestination = findPreference<SwitchPreference>(Key.RESOLVE_DESTINATION)!!
        val resolveDestinationForDirect = findPreference<SwitchPreference>(Key.RESOLVE_DESTINATION_FOR_DIRECT)!!
        val enablePcap = findPreference<SwitchPreference>(Key.ENABLE_PCAP)!!
        enablePcap.isEnabled = tunImplementation.value == "${TunImplementation.GVISOR}"
        val providerRootCA = findPreference<SimpleMenuPreference>(Key.PROVIDER_ROOT_CA)!!

        providerRootCA.setOnPreferenceChangeListener { _, newValue ->
            Libcore.updateSystemRoots((newValue as String).toInt())
            needReload()
            true
        }

        val mtu = findPreference<EditTextPreference>(Key.MTU)!!
        mtu.setOnBindEditTextListener(EditTextPreferenceModifiers.Number)
        val allowAppsBypassVpn = findPreference<SwitchPreference>(Key.ALLOW_APPS_BYPASS_VPN)!!
        val acquireWakelock = findPreference<SwitchPreference>(Key.ACQUIRE_WAKE_LOCK)!!

        val rulesProvider = findPreference<SimpleMenuPreference>(Key.RULES_PROVIDER)!!
        val rulesGeositeUrl = findPreference<LinkOrContentPreference>(Key.RULES_GEOSITE_URL)!!
        val rulesGeoipUrl = findPreference<LinkOrContentPreference>(Key.RULES_GEOIP_URL)!!
        rulesGeositeUrl.isVisible = DataStore.rulesProvider > 2
        rulesGeoipUrl.isVisible = DataStore.rulesProvider > 2
        rulesProvider.setOnPreferenceChangeListener { _, newValue ->
            val provider = (newValue as String).toInt()
            rulesGeositeUrl.isVisible = provider > 2
            rulesGeoipUrl.isVisible = provider > 2
            true
        }

        val fabStyle = findPreference<SimpleMenuPreference>(Key.FAB_STYLE)!!
        fabStyle.setOnPreferenceChangeListener { _, _ ->
            requireActivity().apply {
                this.finish()
                startActivity(intent)
            }
            true
        }
        val enableFragment = findPreference<SwitchPreference>(Key.ENABLE_FRAGMENT)!!
        val enableFragmentForDirect = findPreference<SwitchPreference>(Key.ENABLE_FRAGMENT_FOR_DIRECT)!!
        val fragmentLength = findPreference<EditTextPreference>(Key.FRAGMENT_LENGTH)!!
        val fragmentInterval = findPreference<EditTextPreference>(Key.FRAGMENT_INTERVAL)!!
        enableFragmentForDirect.isVisible = DataStore.enableFragment
        fragmentLength.isVisible = DataStore.enableFragment
        fragmentInterval.isVisible = DataStore.enableFragment
        enableFragment.setOnPreferenceChangeListener { _, newValue ->
            newValue as Boolean
            enableFragmentForDirect.isVisible = newValue
            fragmentLength.isVisible = newValue
            fragmentInterval.isVisible = newValue
            needReload()
            true
        }
        enableFragmentForDirect.onPreferenceChangeListener = reloadListener
        fragmentLength.onPreferenceChangeListener = reloadListener
        fragmentInterval.onPreferenceChangeListener = reloadListener

        speedInterval.onPreferenceChangeListener = reloadListener
        portSocks5.onPreferenceChangeListener = reloadListener
        portHttp.onPreferenceChangeListener = reloadListener
        httpProxyException.onPreferenceChangeListener = reloadListener
        showDirectSpeed.onPreferenceChangeListener = reloadListener
        domainStrategy.onPreferenceChangeListener = reloadListener
        bypassLanInCoreOnly.onPreferenceChangeListener = reloadListener

        remoteDns.onPreferenceChangeListener = reloadListener
        directDns.onPreferenceChangeListener = reloadListener
        enableFakeDns.onPreferenceChangeListener = reloadListener
        hijackDns.onPreferenceChangeListener = reloadListener
        dnsHosts.onPreferenceChangeListener = reloadListener
        enableDnsRouting.onPreferenceChangeListener = reloadListener
        remoteDnsQueryStrategy.onPreferenceChangeListener = reloadListener
        directDnsQueryStrategy.onPreferenceChangeListener = reloadListener
        ednsClientIp.onPreferenceChangeListener = reloadListener

        portLocalDns.onPreferenceChangeListener = reloadListener
        ipv6Mode.onPreferenceChangeListener = reloadListener
        allowAccess.onPreferenceChangeListener = reloadListener

        transproxyPort.onPreferenceChangeListener = reloadListener
        transproxyMode.onPreferenceChangeListener = reloadListener

        logLevel.onPreferenceChangeListener = reloadListener

        shadowsocks2022Implementation.onPreferenceChangeListener = reloadListener
        providerHysteria2.onPreferenceChangeListener = reloadListener
        hysteriaEnablePortHopping.onPreferenceChangeListener = reloadListener
        appTrafficStatistics.onPreferenceChangeListener = reloadListener
        tunImplementation.onPreferenceChangeListener = reloadListener
        destinationOverride.onPreferenceChangeListener = reloadListener
        hijackDns.onPreferenceChangeListener = reloadListener
        resolveDestination.onPreferenceChangeListener = reloadListener
        resolveDestinationForDirect.onPreferenceChangeListener = reloadListener
        mtu.onPreferenceChangeListener = reloadListener
        allowAppsBypassVpn.onPreferenceChangeListener = reloadListener
        acquireWakelock.onPreferenceChangeListener = reloadListener

        tunImplementation.setOnPreferenceChangeListener { _, newValue ->
            enablePcap.isEnabled = newValue == "${TunImplementation.GVISOR}"
            needReload()
            true
        }
        enablePcap.setOnPreferenceChangeListener { _, newValue ->
            if (newValue as Boolean) {
                val path = File(
                    app.getExternalFilesDir(null)?.apply { mkdirs() } ?: app.filesDir,
                    "pcap"
                ).absolutePath
                MaterialAlertDialogBuilder(requireContext()).apply {
                    setTitle(R.string.pcap)
                    setMessage(resources.getString(R.string.pcap_notice, path))
                    setPositiveButton(android.R.string.ok) { _, _ ->
                        needReload()
                    }
                    setNegativeButton(android.R.string.copy) { _, _ ->
                        SagerNet.trySetPrimaryClip(path)
                        snackbar(R.string.copy_success).show()
                    }
                }.show()
            }
            needReload()
            true
        }

    }


    override fun onResume() {
        super.onResume()

        if (::isProxyApps.isInitialized) {
            isProxyApps.isChecked = DataStore.proxyApps
        }
    }

}