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

package io.nekohasekai.sagernet.fmt

import android.Manifest
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.provider.Settings
import cn.hutool.core.codec.Base64
import cn.hutool.json.JSONArray
import cn.hutool.json.JSONObject
import com.github.shadowsocks.plugin.PluginConfiguration
import com.github.shadowsocks.plugin.PluginManager
import com.google.gson.JsonSyntaxException
import io.nekohasekai.sagernet.IPv6Mode
import io.nekohasekai.sagernet.Key
import io.nekohasekai.sagernet.SagerNet
import io.nekohasekai.sagernet.Shadowsocks2022Implementation
import io.nekohasekai.sagernet.bg.VpnService
import io.nekohasekai.sagernet.database.DataStore
import io.nekohasekai.sagernet.database.ProxyEntity
import io.nekohasekai.sagernet.database.SagerDatabase
import io.nekohasekai.sagernet.fmt.V2rayBuildResult.IndexEntity
import io.nekohasekai.sagernet.fmt.gson.gson
import io.nekohasekai.sagernet.fmt.http.HttpBean
import io.nekohasekai.sagernet.fmt.hysteria.HysteriaBean
import io.nekohasekai.sagernet.fmt.hysteria2.Hysteria2Bean
import io.nekohasekai.sagernet.fmt.internal.BalancerBean
import io.nekohasekai.sagernet.fmt.internal.ChainBean
import io.nekohasekai.sagernet.fmt.internal.ConfigBean
import io.nekohasekai.sagernet.fmt.juicity.JuicityBean
import io.nekohasekai.sagernet.fmt.shadowsocks.ShadowsocksBean
import io.nekohasekai.sagernet.fmt.shadowsocksr.ShadowsocksRBean
import io.nekohasekai.sagernet.fmt.shadowtls.ShadowTLSBean
import io.nekohasekai.sagernet.fmt.socks.SOCKSBean
import io.nekohasekai.sagernet.fmt.ssh.SSHBean
import io.nekohasekai.sagernet.fmt.trojan.TrojanBean
import io.nekohasekai.sagernet.fmt.v2ray.StandardV2RayBean
import io.nekohasekai.sagernet.fmt.v2ray.V2RayConfig
import io.nekohasekai.sagernet.fmt.v2ray.V2RayConfig.BrowserDialerObject
import io.nekohasekai.sagernet.fmt.v2ray.V2RayConfig.BrowserForwarderObject
import io.nekohasekai.sagernet.fmt.v2ray.V2RayConfig.DNSOutboundConfigurationObject
import io.nekohasekai.sagernet.fmt.v2ray.V2RayConfig.DnsObject
import io.nekohasekai.sagernet.fmt.v2ray.V2RayConfig.DokodemoDoorInboundConfigurationObject
import io.nekohasekai.sagernet.fmt.v2ray.V2RayConfig.FakeDnsObject
import io.nekohasekai.sagernet.fmt.v2ray.V2RayConfig.FreedomOutboundConfigurationObject
import io.nekohasekai.sagernet.fmt.v2ray.V2RayConfig.GrpcObject
import io.nekohasekai.sagernet.fmt.v2ray.V2RayConfig.HTTPInboundConfigurationObject
import io.nekohasekai.sagernet.fmt.v2ray.V2RayConfig.HTTPOutboundConfigurationObject
import io.nekohasekai.sagernet.fmt.v2ray.V2RayConfig.HTTPUpgradeObject
import io.nekohasekai.sagernet.fmt.v2ray.V2RayConfig.HttpObject
import io.nekohasekai.sagernet.fmt.v2ray.V2RayConfig.Hysteria2Object
import io.nekohasekai.sagernet.fmt.v2ray.V2RayConfig.Hysteria2OutboundConfigurationObject
import io.nekohasekai.sagernet.fmt.v2ray.V2RayConfig.InboundObject
import io.nekohasekai.sagernet.fmt.v2ray.V2RayConfig.KcpObject
import io.nekohasekai.sagernet.fmt.v2ray.V2RayConfig.LazyInboundConfigurationObject
import io.nekohasekai.sagernet.fmt.v2ray.V2RayConfig.LazyOutboundConfigurationObject
import io.nekohasekai.sagernet.fmt.v2ray.V2RayConfig.LogObject
import io.nekohasekai.sagernet.fmt.v2ray.V2RayConfig.MeekObject
import io.nekohasekai.sagernet.fmt.v2ray.V2RayConfig.MekyaObject
import io.nekohasekai.sagernet.fmt.v2ray.V2RayConfig.MultiObservatoryObject
import io.nekohasekai.sagernet.fmt.v2ray.V2RayConfig.ObservatoryObject
import io.nekohasekai.sagernet.fmt.v2ray.V2RayConfig.OutboundObject
import io.nekohasekai.sagernet.fmt.v2ray.V2RayConfig.PolicyObject
import io.nekohasekai.sagernet.fmt.v2ray.V2RayConfig.QuicObject
import io.nekohasekai.sagernet.fmt.v2ray.V2RayConfig.RealityObject
import io.nekohasekai.sagernet.fmt.v2ray.V2RayConfig.ReverseObject
import io.nekohasekai.sagernet.fmt.v2ray.V2RayConfig.RoutingObject
import io.nekohasekai.sagernet.fmt.v2ray.V2RayConfig.RoutingObject.BalancerObject.StrategyObject
import io.nekohasekai.sagernet.fmt.v2ray.V2RayConfig.SSHOutbountConfigurationObject
import io.nekohasekai.sagernet.fmt.v2ray.V2RayConfig.ShadowsocksOutboundConfigurationObject
import io.nekohasekai.sagernet.fmt.v2ray.V2RayConfig.Shadowsocks_2022OutboundConfigurationObject
import io.nekohasekai.sagernet.fmt.v2ray.V2RayConfig.SocksInboundConfigurationObject
import io.nekohasekai.sagernet.fmt.v2ray.V2RayConfig.SocksOutboundConfigurationObject
import io.nekohasekai.sagernet.fmt.v2ray.V2RayConfig.SplitHTTPObject
import io.nekohasekai.sagernet.fmt.v2ray.V2RayConfig.StreamSettingsObject
import io.nekohasekai.sagernet.fmt.v2ray.V2RayConfig.TLSObject
import io.nekohasekai.sagernet.fmt.v2ray.V2RayConfig.TcpObject
import io.nekohasekai.sagernet.fmt.v2ray.V2RayConfig.TrojanOutboundConfigurationObject
import io.nekohasekai.sagernet.fmt.v2ray.V2RayConfig.VLESSOutboundConfigurationObject
import io.nekohasekai.sagernet.fmt.v2ray.V2RayConfig.VMessOutboundConfigurationObject
import io.nekohasekai.sagernet.fmt.v2ray.V2RayConfig.WebSocketObject
import io.nekohasekai.sagernet.fmt.v2ray.V2RayConfig.WireGuardOutboundConfigurationObject
import io.nekohasekai.sagernet.fmt.v2ray.VLESSBean
import io.nekohasekai.sagernet.fmt.v2ray.VMessBean
import io.nekohasekai.sagernet.fmt.wireguard.WireGuardBean
import io.nekohasekai.sagernet.ktx.app
import io.nekohasekai.sagernet.ktx.isIpAddress
import io.nekohasekai.sagernet.ktx.joinHostPort
import io.nekohasekai.sagernet.ktx.listByLineOrComma
import io.nekohasekai.sagernet.ktx.mkPort
import io.nekohasekai.sagernet.ktx.toHysteriaPort
import io.nekohasekai.sagernet.utils.PackageCache

const val TAG_SOCKS = "socks"
const val TAG_HTTP = "http"
const val TAG_TRANS = "trans"

const val TAG_AGENT = "proxy"
const val TAG_DIRECT = "direct"
const val TAG_BYPASS = "bypass"
const val TAG_BLOCK = "block"

const val TAG_DNS_IN = "dns-in"
const val TAG_DNS_OUT = "dns-out"

const val TAG_DNS_DIRECT = "dns-direct"

const val LOCALHOST = "127.0.0.1"

class V2rayBuildResult(
    var config: String,
    var index: List<IndexEntity>,
    var requireWs: Boolean,
    var wsPort: Int,
    var requireSh: Boolean,
    var shPort: Int,
    var outboundTags: List<String>,
    var outboundTagsCurrent: List<String>,
    var outboundTagsAll: Map<String, ProxyEntity>,
    var bypassTag: String,
    var observerTag: String,
    var observatoryTags: Set<String>,
    val dumpUid: Boolean,
    val alerts: List<Pair<Int, String>>,
) {
    data class IndexEntity(var isBalancer: Boolean, var chain: LinkedHashMap<Int, ProxyEntity>)
}

fun buildV2RayConfig(
    proxy: ProxyEntity, forTest: Boolean = false
): V2rayBuildResult {

    val outboundTags = ArrayList<String>()
    val outboundTagsCurrent = ArrayList<String>()
    val outboundTagsAll = HashMap<String, ProxyEntity>()
    val globalOutbounds = ArrayList<String>()

    fun ProxyEntity.resolveChain(): MutableList<ProxyEntity> {
        val bean = requireBean()
        if (bean is ChainBean) {
            val beans = SagerDatabase.proxyDao.getEntities(bean.proxies)
            val beansMap = beans.associateBy { it.id }
            val beanList = ArrayList<ProxyEntity>()
            for (proxyId in bean.proxies) {
                val item = beansMap[proxyId] ?: continue
                if (!item.requireBean().canMapping()) error("Some configurations are incompatible with chain.")
                beanList.addAll(item.resolveChain())
            }
            return beanList.asReversed()
        } else if (bean is BalancerBean) {
            val beans = if (bean.type == BalancerBean.TYPE_LIST) {
                SagerDatabase.proxyDao.getEntities(bean.proxies)
            } else {
                SagerDatabase.proxyDao.getByGroup(bean.groupId)
            }

            val beansMap = beans.associateBy { it.id }
            val beanList = ArrayList<ProxyEntity>()
            for (proxyId in beansMap.keys) {
                val item = beansMap[proxyId] ?: continue
                if (item.id == id) continue
                when (item.type) {
                    ProxyEntity.TYPE_BALANCER -> error("Nested balancers are not supported")
                    ProxyEntity.TYPE_CHAIN -> error("Chain is incompatible with balancer")
                }
                beanList.add(item)
            }
            return beanList
        }

        val list = mutableListOf(this)

        val groupId = SagerDatabase.groupDao.getById(groupId)
        val frontProxy = groupId?.frontProxy?.let { SagerDatabase.proxyDao.getById(it) }
        val landingProxy = groupId?.landingProxy?.let { SagerDatabase.proxyDao.getById(it) }
        if (frontProxy != null) {
            list.add(frontProxy)
        }
        if (landingProxy != null) {
            list.add(0, landingProxy)
        }
        return list
    }

    val proxies = proxy.resolveChain()
    val extraRules = if (forTest) listOf() else SagerDatabase.rulesDao.enabledRules()
    val extraProxies = if (forTest) mapOf() else SagerDatabase.proxyDao.getEntities(extraRules.mapNotNull { rule ->
        rule.outbound.takeIf { it > 0 && it != proxy.id }
    }.toHashSet().toList()).associate {
        (it.id to ((it.type == ProxyEntity.TYPE_BALANCER) to lazy {
            it.balancerBean
        })) to it.resolveChain()
    }

    val allowAccess = DataStore.allowAccess
    val bind = if (!forTest && allowAccess) "0.0.0.0" else LOCALHOST

    val remoteDns = DataStore.remoteDns.listByLineOrComma().filter { !it.startsWith("#") }
    var directDNS = DataStore.directDns.listByLineOrComma().filter { !it.startsWith("#") }
    var bootstrapDNS = DataStore.bootstrapDns.listByLineOrComma().filter { !it.startsWith("#") }
    if (DataStore.useLocalDnsAsDirectDns) directDNS = listOf("localhost")
    if (DataStore.useLocalDnsAsBootstrapDns) bootstrapDNS = listOf("localhost")
    val enableDnsRouting = DataStore.enableDnsRouting
    val useFakeDns = DataStore.enableFakeDns
    val hijackDns = DataStore.hijackDns
    val remoteDnsQueryStrategy = DataStore.remoteDnsQueryStrategy
    val directDnsQueryStrategy = DataStore.directDnsQueryStrategy
    val trafficSniffing = DataStore.trafficSniffing
    val indexMap = ArrayList<IndexEntity>()
    var requireWs = false
    var requireSh = false
    val requireHttp = !forTest && DataStore.requireHttp
    val requireTransproxy = if (forTest) false else DataStore.requireTransproxy
    val ipv6Mode = if (forTest) IPv6Mode.ENABLE else DataStore.ipv6Mode
    val resolveDestination = DataStore.resolveDestination
    val destinationOverride = DataStore.destinationOverride
    val trafficStatistics = !forTest && DataStore.profileTrafficStatistics

    val outboundDomainStrategy = when {
        !resolveDestination -> "AsIs"
        ipv6Mode == IPv6Mode.DISABLE -> "UseIPv4"
        ipv6Mode == IPv6Mode.PREFER -> "PreferIPv6"
        ipv6Mode == IPv6Mode.ONLY -> "UseIPv6"
        else -> "PreferIPv4"
    }

    var dumpUid = false
    val alerts = mutableListOf<Pair<Int, String>>()

    lateinit var result: V2rayBuildResult
    V2RayConfig().apply {

        dns = DnsObject().apply {
            hosts = DataStore.hosts.split("\n")
                .filter { it.isNotBlank() }
                .associate { it.substringBefore(" ") to it.substringAfter(" ") }
                .toMutableMap()
            servers = mutableListOf()
            fallbackStrategy = "disabledIfAnyMatch"
        }

        log = LogObject().apply {
            loglevel = if (DataStore.enableLog) "debug" else "error"
        }

        policy = PolicyObject().apply {
            levels = mapOf(
                // dns
                "1" to PolicyObject.LevelPolicyObject().apply {
                    connIdle = 30
                })

            if (trafficStatistics) {
                system = PolicyObject.SystemPolicyObject().apply {
                    statsOutboundDownlink = true
                    statsOutboundUplink = true
                }
            }
        }
        inbounds = mutableListOf()

        if (!forTest) inbounds.add(InboundObject().apply {
            tag = TAG_SOCKS
            listen = bind
            port = DataStore.socksPort
            protocol = "socks"
            settings = LazyInboundConfigurationObject(this,
                SocksInboundConfigurationObject().apply {
                    auth = "noauth"
                    udp = true
                })
            if (trafficSniffing || useFakeDns) {
                sniffing = InboundObject.SniffingObject().apply {
                    enabled = true
                    destOverride = when {
                        useFakeDns && !trafficSniffing -> listOf("fakedns")
                        useFakeDns -> listOf("fakedns", "http", "tls", "quic")
                        else -> listOf("http", "tls", "quic")
                    }
                    metadataOnly = useFakeDns && !trafficSniffing
                    routeOnly = !destinationOverride
                }
            }
        })

        if (requireHttp) {
            inbounds.add(InboundObject().apply {
                tag = TAG_HTTP
                listen = bind
                port = DataStore.httpPort
                protocol = "http"
                settings = LazyInboundConfigurationObject(this,
                    HTTPInboundConfigurationObject().apply {
                        allowTransparent = true
                    })
                if (trafficSniffing || useFakeDns) {
                    sniffing = InboundObject.SniffingObject().apply {
                        enabled = true
                        destOverride = when {
                            useFakeDns && !trafficSniffing -> listOf("fakedns")
                            useFakeDns -> listOf("fakedns", "http", "tls", "quic")
                            else -> listOf("http", "tls", "quic")
                        }
                        metadataOnly = useFakeDns && !trafficSniffing
                        routeOnly = !destinationOverride
                    }
                }
            })
        }

        if (requireTransproxy) {
            inbounds.add(InboundObject().apply {
                tag = TAG_TRANS
                listen = bind
                port = DataStore.transproxyPort
                protocol = "dokodemo-door"
                settings = LazyInboundConfigurationObject(this,
                    DokodemoDoorInboundConfigurationObject().apply {
                        network = "tcp,udp"
                        followRedirect = true
                    })
                if (trafficSniffing || useFakeDns) {
                    sniffing = InboundObject.SniffingObject().apply {
                        enabled = true
                        destOverride = when {
                            useFakeDns && !trafficSniffing -> listOf("fakedns")
                            useFakeDns -> listOf("fakedns", "http", "tls", "quic")
                            else -> listOf("http", "tls", "quic")
                        }
                        metadataOnly = useFakeDns && !trafficSniffing
                        routeOnly = !destinationOverride
                    }
                }
                when (DataStore.transproxyMode) {
                    1 -> streamSettings = StreamSettingsObject().apply {
                        sockopt = StreamSettingsObject.SockoptObject().apply {
                            tproxy = "tproxy"
                        }
                    }
                }
            })
        }

        outbounds = mutableListOf()

        routing = RoutingObject().apply {
            domainStrategy = DataStore.domainStrategy

            rules = mutableListOf()

            val wsRules = HashMap<String, RoutingObject.RuleObject>()

            for (proxyEntity in proxies) {
                val bean = proxyEntity.requireBean()

                if (bean is StandardV2RayBean && (
                    (bean.type == "ws" && bean.wsUseBrowserForwarder) ||
                    (bean.type == "splithttp" && bean.security == "tls" && bean.shUseBrowserForwarder)
                )) {
                    val route = RoutingObject.RuleObject().apply {
                        type = "field"
                        outboundTag = TAG_DIRECT
                        when {
                            bean.host.isIpAddress() -> {
                                ip = listOf(bean.host)
                                if (DataStore.domainStrategy != "AsIs") {
                                    skipDomain = true
                                }
                            }
                            bean.host.isNotBlank() -> {
                                domain = listOf(bean.host)
                            }
                            bean.serverAddress.isIpAddress() -> {
                                ip = listOf(bean.serverAddress)
                                if (DataStore.domainStrategy != "AsIs") {
                                    skipDomain = true
                                }
                            }
                            else -> domain = listOf(bean.serverAddress)
                        }
                    }
                    wsRules[bean.host.takeIf { !it.isNullOrBlank() } ?: bean.serverAddress] = route
                }

            }

            rules.addAll(wsRules.values)
        }

        var rootBalancer: RoutingObject.RuleObject? = null
        var rootObserver: MultiObservatoryObject.MultiObservatoryItem? = null

        fun buildChain(
            tagOutbound: String,
            profileList: List<ProxyEntity>,
            isBalancer: Boolean,
            balancer: () -> BalancerBean?,
        ): String {
            var pastExternal = false
            lateinit var pastOutbound: OutboundObject
            lateinit var currentOutbound: OutboundObject
            lateinit var pastInboundTag: String
            val chainMap = LinkedHashMap<Int, ProxyEntity>()
            indexMap.add(IndexEntity(isBalancer, chainMap))
            val chainOutbounds = ArrayList<OutboundObject>()
            var chainOutbound = ""

            profileList.forEachIndexed { index, proxyEntity ->
                val bean = proxyEntity.requireBean()
                currentOutbound = OutboundObject()

                val tagIn: String
                var needGlobal: Boolean

                if (isBalancer || index == profileList.lastIndex && !pastExternal) {
                    tagIn = "$TAG_AGENT-global-${proxyEntity.id}"
                    needGlobal = true
                } else {
                    tagIn = if (index == 0) tagOutbound else {
                        "$tagOutbound-${proxyEntity.id}"
                    }
                    needGlobal = false
                }

                if (index == 0) {
                    chainOutbound = tagIn
                }

                if (needGlobal) {
                    if (!globalOutbounds.contains(tagIn)) {
                        needGlobal = false
                        globalOutbounds.add(tagIn)
                    }
                }

                if (!needGlobal) {

                    outboundTagsAll[tagIn] = proxyEntity

                    if (isBalancer || index == 0) {
                        outboundTags.add(tagIn)
                        if (tagOutbound == TAG_AGENT) {
                            outboundTagsCurrent.add(tagIn)
                        }
                    }

                    var currentDomainStrategy = outboundDomainStrategy

                    if (proxyEntity.needExternal()) {
                        val localPort = mkPort()
                        chainMap[localPort] = proxyEntity
                        if (bean is ShadowTLSBean) {
                            currentOutbound.apply {
                                protocol = "freedom"
                                settings = LazyOutboundConfigurationObject(this,
                                    FreedomOutboundConfigurationObject().apply {
                                        redirect = joinHostPort(LOCALHOST, localPort)
                                    })
                            }
                        } else {
                            currentOutbound.apply {
                                protocol = "socks"
                                settings = LazyOutboundConfigurationObject(this,
                                    SocksOutboundConfigurationObject().apply {
                                        servers = listOf(SocksOutboundConfigurationObject.ServerObject()
                                            .apply {
                                                address = LOCALHOST
                                                port = localPort
                                            })
                                    })
                            }
                        }
                    } else {
                        currentOutbound.apply {
                            if (bean is StandardV2RayBean) {
                                if (bean is VMessBean) {
                                    protocol = "vmess"
                                    settings = LazyOutboundConfigurationObject(this,
                                        VMessOutboundConfigurationObject().apply {
                                            vnext = listOf(VMessOutboundConfigurationObject.ServerObject()
                                                .apply {
                                                    address = bean.serverAddress
                                                    port = bean.serverPort
                                                    users = listOf(VMessOutboundConfigurationObject.ServerObject.UserObject()
                                                        .apply {
                                                            id = bean.uuidOrGenerate()
                                                            if (bean.alterId > 0) {
                                                                alterId = bean.alterId
                                                            }
                                                            security = bean.encryption.takeIf { it.isNotBlank() }
                                                                ?: "auto"
                                                            experiments = ""
                                                            if (bean.experimentalAuthenticatedLength) {
                                                                experiments += "AuthenticatedLength"
                                                            }
                                                            if (bean.experimentalNoTerminationSignal) {
                                                                if (experiments != "") {
                                                                    experiments += "|"
                                                                }
                                                                experiments += "NoTerminationSignal"
                                                            }
                                                            if (experiments.isBlank()) experiments = null
                                                        })
                                                })
                                            when (bean.packetEncoding) {
                                                "packet" -> {
                                                    packetEncoding = "packet"
                                                }
                                                "xudp" -> {
                                                    packetEncoding = "xudp"
                                                }
                                            }
                                        })
                                } else if (bean is VLESSBean) {
                                    protocol = "vless"
                                    settings = LazyOutboundConfigurationObject(this,
                                        VLESSOutboundConfigurationObject().apply {
                                            vnext = listOf(VLESSOutboundConfigurationObject.ServerObject()
                                                .apply {
                                                    address = bean.serverAddress
                                                    port = bean.serverPort
                                                    users = listOf(VLESSOutboundConfigurationObject.ServerObject.UserObject()
                                                        .apply {
                                                            id = bean.uuidOrGenerate()
                                                            encryption = bean.encryption
                                                            if (bean.flow.isNotBlank()) {
                                                                flow = bean.flow
                                                            }
                                                        })
                                                })
                                            when (bean.packetEncoding) {
                                                "packet" -> {
                                                    packetEncoding = "packet"
                                                }
                                                "xudp" -> {
                                                    packetEncoding = "xudp"
                                                }
                                            }
                                        })
                                } else if (bean is TrojanBean) {
                                    protocol = "trojan"
                                    settings = LazyOutboundConfigurationObject(this,
                                        TrojanOutboundConfigurationObject().apply {
                                            servers = listOf(TrojanOutboundConfigurationObject.ServerObject()
                                                .apply {
                                                    address = bean.serverAddress
                                                    port = bean.serverPort
                                                    password = bean.password
                                                })
                                        })
                                } else if (bean is ShadowsocksBean) {
                                    if (bean.method.startsWith("2022-blake3-") && DataStore.shadowsocks2022Implementation == Shadowsocks2022Implementation.V2FLY_V2RAY_CORE) {
                                        protocol = "shadowsocks2022"
                                        settings = LazyOutboundConfigurationObject(this,
                                            Shadowsocks_2022OutboundConfigurationObject().apply {
                                                address = bean.serverAddress
                                                port = bean.serverPort
                                                method = bean.method
                                                val keys = bean.password.split(":")
                                                if (keys.size == 1) {
                                                    psk = keys[0]
                                                }
                                                if (keys.size > 1) {
                                                    ipsk = mutableListOf()
                                                    for (i in 0..(keys.size - 2)) {
                                                        ipsk.add(keys[i])
                                                    }
                                                    psk = keys[keys.size - 1]
                                                }
                                                if (bean.plugin.isNotBlank()) {
                                                    val pluginConfiguration = PluginConfiguration(bean.plugin)
                                                    try {
                                                        PluginManager.init(pluginConfiguration)?.let { (path, opts, _) ->
                                                            plugin = path
                                                            pluginOpts = opts.toString()
                                                        }
                                                    } catch (e: PluginManager.PluginNotFoundException) {
                                                        if (e.plugin in arrayOf("v2ray-plugin", "obfs-local")) {
                                                            plugin = e.plugin
                                                            pluginOpts = pluginConfiguration.getOptions().toString()
                                                        } else {
                                                            throw e
                                                        }
                                                    }
                                                }
                                            }
                                        )
                                    } else {
                                        protocol = "shadowsocks"
                                        settings = LazyOutboundConfigurationObject(this,
                                            ShadowsocksOutboundConfigurationObject().apply {
                                                servers = listOf(ShadowsocksOutboundConfigurationObject.ServerObject().apply {
                                                    address = bean.serverAddress
                                                    port = bean.serverPort
                                                    password = bean.password
                                                        method = bean.method
                                                    if (!bean.method.startsWith("2022-blake3-") && bean.experimentReducedIvHeadEntropy) {
                                                        experimentReducedIvHeadEntropy = bean.experimentReducedIvHeadEntropy
                                                    }
                                                    if (bean.plugin.isNotBlank()) {
                                                        val pluginConfiguration = PluginConfiguration(bean.plugin)
                                                        try {
                                                            PluginManager.init(pluginConfiguration)?.let { (path, opts, _) ->
                                                                plugin = path
                                                                pluginOpts = opts.toString()
                                                            }
                                                        } catch (e: PluginManager.PluginNotFoundException) {
                                                            if (e.plugin in arrayOf("v2ray-plugin", "obfs-local")) {
                                                                plugin = e.plugin
                                                                pluginOpts = pluginConfiguration.getOptions().toString()
                                                            } else {
                                                                throw e
                                                            }
                                                        }
                                                    }
                                                })
                                            }
                                        )
                                    }
                                } else if (bean is SOCKSBean) {
                                    protocol = "socks"
                                    settings = LazyOutboundConfigurationObject(this,
                                        SocksOutboundConfigurationObject().apply {
                                            servers = listOf(SocksOutboundConfigurationObject.ServerObject().apply {
                                                address = bean.serverAddress
                                                port = bean.serverPort
                                                if (!bean.username.isNullOrBlank()) {
                                                    users = listOf(SocksOutboundConfigurationObject.ServerObject.UserObject().apply {
                                                        user = bean.username
                                                        if (!bean.password.isNullOrBlank() && bean.protocolName() == "SOCKS5") {
                                                            pass = bean.password
                                                        }
                                                    })
                                                }
                                            })
                                            version = bean.protocolVersionName()
                                        }
                                    )
                                } else if (bean is HttpBean) {
                                    protocol = "http"
                                    settings = LazyOutboundConfigurationObject(this,
                                        HTTPOutboundConfigurationObject().apply {
                                            servers = listOf(HTTPOutboundConfigurationObject.ServerObject().apply {
                                                address = bean.serverAddress
                                                port = bean.serverPort
                                                if (!bean.username.isNullOrBlank()) {
                                                    users = listOf(HTTPInboundConfigurationObject.AccountObject().apply {
                                                        user = bean.username
                                                        pass = bean.password
                                                    })
                                                }
                                            })
                                        }
                                    )
                                }

                                streamSettings = StreamSettingsObject().apply {
                                    network = bean.type
                                    if (bean.security.isNotBlank()) {
                                        security = bean.security
                                    }
                                    when (security) {
                                        "tls" -> {
                                            tlsSettings = TLSObject().apply {
                                                if (bean.sni.isNotBlank()) {
                                                    serverName = bean.sni
                                                }

                                                if (bean.alpn.isNotBlank()) {
                                                    alpn = bean.alpn.listByLineOrComma()
                                                }

                                                if (bean.certificates.isNotBlank()) {
                                                    disableSystemRoot = true
                                                    certificates = listOf(TLSObject.CertificateObject()
                                                        .apply {
                                                            usage = "verify"
                                                            certificate = bean.certificates.split(
                                                                "\n"
                                                            ).filter { it.isNotBlank() }
                                                        })
                                                }

                                                if (bean.pinnedPeerCertificateChainSha256.isNotBlank()) {
                                                    pinnedPeerCertificateChainSha256 = bean.pinnedPeerCertificateChainSha256.listByLineOrComma()
                                                }

                                                if (bean.allowInsecure) {
                                                    allowInsecure = true
                                                }
                                                if (bean.utlsFingerprint.isNotBlank()) {
                                                    fingerprint = bean.utlsFingerprint
                                                }
                                                if (bean.echConfig.isNotBlank()) {
                                                    echConfig = bean.echConfig
                                                }
                                                if (bean.echDohServer.isNotBlank()) {
                                                    echDohServer = bean.echDohServer
                                                }
                                            }
                                        }
                                        "reality" -> {
                                            realitySettings = RealityObject().apply {
                                                if (bean.sni.isNotBlank()) {
                                                    serverName = bean.sni
                                                }
                                                if (bean.realityPublicKey.isNotBlank()) {
                                                    publicKey = bean.realityPublicKey
                                                }
                                                if (bean.realityShortId.isNotBlank()) {
                                                    shortId = bean.realityShortId
                                                }
                                                if (bean.realitySpiderX.isNotBlank()) {
                                                    spiderX = bean.realitySpiderX
                                                }
                                                if (bean.realityFingerprint.isNotBlank()) {
                                                    fingerprint = bean.realityFingerprint
                                                }
                                            }
                                        }
                                    }

                                    when (network) {
                                        "tcp" -> {
                                            tcpSettings = TcpObject().apply {
                                                if (bean.headerType == "http") {
                                                    header = TcpObject.HeaderObject().apply {
                                                        type = "http"
                                                        if (bean.host.isNotBlank() || bean.path.isNotBlank()) {
                                                            request = TcpObject.HeaderObject.HTTPRequestObject()
                                                                .apply {
                                                                    headers = mutableMapOf()
                                                                    if (bean.host.isNotBlank()) {
                                                                        headers["Host"] = TcpObject.HeaderObject.StringOrListObject()
                                                                            .apply {
                                                                                valueY = bean.host.listByLineOrComma()
                                                                            }
                                                                    }
                                                                    if (bean.path.isNotBlank()) {
                                                                        path = bean.path.listByLineOrComma()
                                                                    }
                                                                }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                        "kcp" -> {
                                            kcpSettings = KcpObject().apply {
                                                mtu = 1350
                                                tti = 50
                                                uplinkCapacity = 12
                                                downlinkCapacity = 100
                                                congestion = false
                                                readBufferSize = 1
                                                writeBufferSize = 1
                                                header = KcpObject.HeaderObject().apply {
                                                    type = bean.headerType
                                                }
                                                if (bean.mKcpSeed.isNotBlank()) {
                                                    seed = bean.mKcpSeed
                                                }
                                            }
                                        }
                                        "ws" -> {
                                            wsSettings = WebSocketObject().apply {
                                                headers = mutableMapOf()

                                                if (bean.host.isNotBlank()) {
                                                    headers["Host"] = bean.host
                                                }

                                                path = bean.path.takeIf { it.isNotBlank() } ?: "/"

                                                if (bean.wsMaxEarlyData > 0) {
                                                    maxEarlyData = bean.wsMaxEarlyData
                                                }

                                                if (bean.earlyDataHeaderName.isNotBlank()) {
                                                    earlyDataHeaderName = bean.earlyDataHeaderName
                                                }

                                                if (bean.wsUseBrowserForwarder) {
                                                    useBrowserForwarding = true
                                                    requireWs = true
                                                }
                                            }
                                        }
                                        "http" -> {
                                            network = "http"

                                            httpSettings = HttpObject().apply {
                                                if (bean.host.isNotBlank()) {
                                                    host = bean.host.listByLineOrComma()
                                                }

                                                path = bean.path.takeIf { it.isNotBlank() } ?: "/"
                                            }
                                        }
                                        "quic" -> {
                                            quicSettings = QuicObject().apply {
                                                security = bean.quicSecurity.takeIf { it.isNotBlank() }
                                                    ?: "none"
                                                key = bean.quicKey
                                                header = QuicObject.HeaderObject().apply {
                                                    type = bean.headerType.takeIf { it.isNotBlank() }
                                                        ?: "none"
                                                }
                                            }
                                        }
                                        "grpc" -> {
                                            grpcSettings = GrpcObject().apply {
                                                serviceName = bean.grpcServiceName
                                            }
                                        }
                                        "meek" -> {
                                            meekSettings = MeekObject().apply {
                                                if (bean.meekUrl.isNotBlank()) {
                                                    url = bean.meekUrl
                                                }
                                            }
                                        }
                                        "httpupgrade" -> {
                                            httpupgradeSettings = HTTPUpgradeObject().apply {
                                                if (bean.host.isNotBlank()) {
                                                    host = bean.host
                                                }
                                                if (bean.path.isNotBlank()) {
                                                    path = bean.path
                                                }
                                            }
                                        }
                                        "splithttp" -> {
                                            splithttpSettings = SplitHTTPObject().apply {
                                                if (bean.host.isNotBlank()) {
                                                    host = bean.host
                                                }
                                                if (bean.path.isNotBlank()) {
                                                    path = bean.path
                                                }
                                                if (bean.security == "tls" && bean.shUseBrowserForwarder) {
                                                    useBrowserForwarding = true
                                                    requireSh = true
                                                }
                                            }
                                        }
                                        "hysteria2" -> {
                                            hy2Settings = Hysteria2Object().apply {
                                                if (bean.hy2Password.isNotBlank()) {
                                                    password = bean.hy2Password
                                                }
                                                congestion = Hysteria2Object.CongestionObject().apply {
                                                    down_mbps = bean.hy2DownMbps
                                                    up_mbps = bean.hy2UpMbps
                                                }
                                                if (bean.hy2ObfsPassword.isNotBlank()) {
                                                    obfs = Hysteria2Object.OBFSObject().apply {
                                                        type = "salamander"
                                                        password = bean.hy2ObfsPassword
                                                    }
                                                }
                                            }
                                        }
                                        "mekya" -> {
                                            mekyaSettings = MekyaObject().apply {
                                                kcp = KcpObject().apply {
                                                    mtu = 1350
                                                    tti = 50
                                                    uplinkCapacity = 12
                                                    downlinkCapacity = 100
                                                    congestion = false
                                                    readBufferSize = 1
                                                    writeBufferSize = 1
                                                    header = KcpObject.HeaderObject().apply {
                                                        type = bean.mekyaKcpHeaderType
                                                    }
                                                    if (bean.mKcpSeed.isNotBlank()) {
                                                        seed = bean.mekyaKcpSeed
                                                    }
                                                }
                                                if (bean.mekyaUrl.isNotBlank()) {
                                                    url = bean.mekyaUrl
                                                }
                                                // magic values from https://github.com/v2fly/v2ray-core/pull/3120
                                                maxWriteDelay = 80
                                                maxRequestSize = 96000
                                                pollingIntervalInitial = 200
                                                h2PoolSize = 8
                                            }
                                        }
                                    }
                                    if (DataStore.enableFragment && bean.canTCPing()
                                        && (security == "tls" || security == "reality")
                                        && !(bean is ShadowsocksBean && bean.plugin.isNotEmpty()
                                        && !(network == "ws" && bean.wsUseBrowserForwarder)
                                        && !(network == "splithttp" && bean.security == "tls" && bean.shUseBrowserForwarder))
                                    ) {
                                        sockopt = StreamSettingsObject.SockoptObject().apply {
                                            if (DataStore.enableFragment) {
                                                fragment = StreamSettingsObject.SockoptObject.FragmentObject().apply {
                                                    packets = "tlshello"
                                                    length = DataStore.fragmentLength
                                                    interval = DataStore.fragmentInterval
                                                }
                                            }
                                        }
                                    }
                                }
                            } else if (bean is ShadowsocksRBean) {
                                protocol = "shadowsocks"
                                settings = LazyOutboundConfigurationObject(this,
                                    ShadowsocksOutboundConfigurationObject().apply {
                                        servers = listOf(ShadowsocksOutboundConfigurationObject.ServerObject().apply {
                                                address = bean.serverAddress
                                                port = bean.serverPort
                                                method = bean.method
                                                password = bean.password
                                            }
                                        )
                                        plugin = "shadowsocksr"
                                        pluginArgs = listOf(
                                            "--obfs=${bean.obfs}",
                                            "--obfs-param=${bean.obfsParam}",
                                            "--protocol=${bean.protocol}",
                                            "--protocol-param=${bean.protocolParam}"
                                        )
                                    }
                                )
                            } else if (bean is WireGuardBean) {
                                protocol = "wireguard"
                                settings = LazyOutboundConfigurationObject(this,
                                    WireGuardOutboundConfigurationObject().apply {
                                        address = bean.localAddress.listByLineOrComma()
                                        secretKey = bean.privateKey
                                        mtu = bean.mtu
                                        val values = bean.reserved.listByLineOrComma()
                                        if (values.size == 3) {
                                            val reserved0 = values[0].toIntOrNull()
                                            val reserved1 = values[1].toIntOrNull()
                                            val reserved2 = values[2].toIntOrNull()
                                            if (reserved0 != null && reserved1 != null && reserved2 != null) {
                                                reserved = listOf(reserved0, reserved1, reserved2)
                                            }
                                        } else {
                                            val array = Base64.decode(bean.reserved)
                                            if (array.size == 3) {
                                                reserved = listOf(array[0].toUByte().toInt(), array[1].toUByte().toInt(), array[2].toUByte().toInt())
                                            }
                                        }
                                        peers = listOf(WireGuardOutboundConfigurationObject.WireGuardPeerObject().apply {
                                            publicKey = bean.peerPublicKey
                                            if (bean.peerPreSharedKey.isNotBlank()) {
                                                preSharedKey = bean.peerPreSharedKey
                                            }
                                            endpoint = joinHostPort(bean.finalAddress, bean.finalPort)
                                        })
                                    })
                                if (currentDomainStrategy == "AsIs") {
                                    currentDomainStrategy = "UseIP"
                                }
                            } else if (bean is SSHBean) {
                                protocol = "ssh"
                                settings = LazyOutboundConfigurationObject(this,
                                    SSHOutbountConfigurationObject().apply {
                                        address = bean.finalAddress
                                        port = bean.finalPort
                                        user = bean.username
                                        when (bean.authType) {
                                            SSHBean.AUTH_TYPE_PRIVATE_KEY -> {
                                                privateKey = bean.privateKey
                                                password = bean.privateKeyPassphrase
                                            }
                                            SSHBean.AUTH_TYPE_PASSWORD -> {
                                                password = bean.password
                                            }
                                        }
                                        publicKey = bean.publicKey
                                    })
                            } else if (bean is Hysteria2Bean) {
                                protocol = "hysteria2"
                                settings = LazyOutboundConfigurationObject(this,
                                    Hysteria2OutboundConfigurationObject().apply {
                                        servers = listOf(Hysteria2OutboundConfigurationObject.ServerObject().apply {
                                            address = bean.serverAddress
                                            port = bean.serverPorts.toHysteriaPort()
                                        })
                                    }
                                )
                                streamSettings = StreamSettingsObject().apply {
                                    network = "hysteria2"
                                    security = "tls"
                                    hy2Settings = Hysteria2Object().apply {
                                        use_udp_extension = true
                                        if (bean.auth.isNotBlank()) {
                                            password = bean.auth
                                        }
                                        congestion = Hysteria2Object.CongestionObject().apply {
                                            down_mbps = bean.downloadMbps
                                            up_mbps = bean.uploadMbps
                                        }
                                        if (bean.obfs.isNotBlank()) {
                                            obfs = Hysteria2Object.OBFSObject().apply {
                                                type = "salamander"
                                                password = bean.obfs
                                            }
                                        }
                                    }
                                    tlsSettings = TLSObject().apply {
                                        if (bean.sni.isNotBlank()) {
                                            serverName = bean.sni
                                        }
                                        if (bean.allowInsecure) {
                                            allowInsecure = true
                                        }
                                        if (bean.caText.isNotBlank()) {
                                            disableSystemRoot = true
                                            certificates = listOf(TLSObject.CertificateObject().apply {
                                                usage = "verify"
                                                certificate = bean.caText.split("\n").filter { it.isNotBlank() }
                                            })
                                        }
                                    }
                                }
                            }
                            if (bean is StandardV2RayBean && bean.mux) {
                                mux = OutboundObject.MuxObject().apply {
                                    enabled = true
                                    concurrency = bean.muxConcurrency
                                    when (bean.muxPacketEncoding) {
                                        "packet" -> {
                                            packetEncoding = "packet"
                                        }
                                        "xudp" -> {
                                            packetEncoding = "xudp"
                                        }
                                    }
                                }
                            }
                        }
                    }

                    currentOutbound.domainStrategy = currentDomainStrategy

                    if (bean is JuicityBean && DataStore.enableFakeDns && currentOutbound.domainStrategy == "AsIs") {
                        currentOutbound.domainStrategy = "UseIP" // https://github.com/juicity/juicity/issues/140
                    }

                    if (bean is ConfigBean && bean.type == "v2ray_outbound") {
                        currentOutbound = gson.fromJson(bean.content, OutboundObject::class.java).apply { init() }
                    }

                    currentOutbound.tag = tagIn

                }

                if (!isBalancer && index > 0) {
                    if (!pastExternal) {
                        pastOutbound.proxySettings = OutboundObject.ProxySettingsObject().apply {
                            tag = tagIn
                            transportLayer = true
                        }
                    } else {
                        routing.rules.add(RoutingObject.RuleObject().apply {
                            type = "field"
                            inboundTag = listOf(pastInboundTag)
                            outboundTag = tagIn
                        })
                    }
                }

                if (proxyEntity.needExternal() && !isBalancer && index != profileList.lastIndex) {
                    val mappingPort = mkPort()
                    bean.finalAddress = LOCALHOST
                    bean.finalPort = mappingPort
                    bean.isChain = true

                    inbounds.add(InboundObject().apply {
                        listen = LOCALHOST
                        port = mappingPort
                        tag = "$tagOutbound-mapping-${proxyEntity.id}"
                        protocol = "dokodemo-door"
                        settings = LazyInboundConfigurationObject(this,
                            DokodemoDoorInboundConfigurationObject().apply {
                                address = bean.serverAddress
                                network = bean.network()
                                port = when (bean) {
                                    is HysteriaBean -> {
                                        bean.serverPorts.toHysteriaPort()
                                    }
                                    is Hysteria2Bean -> {
                                        bean.serverPorts.toHysteriaPort()
                                    }
                                    else -> {
                                        bean.serverPort
                                    }
                                }
                            })

                        pastInboundTag = tag
                    })
                } else if (bean.canMapping() && proxyEntity.needExternal()) {
                    val mappingPort = mkPort()
                    bean.finalAddress = LOCALHOST
                    bean.finalPort = mappingPort

                    inbounds.add(InboundObject().apply {
                        listen = LOCALHOST
                        port = mappingPort
                        tag = "$tagOutbound-mapping-${proxyEntity.id}"
                        protocol = "dokodemo-door"
                        settings = LazyInboundConfigurationObject(this,
                            DokodemoDoorInboundConfigurationObject().apply {
                                address = bean.serverAddress
                                network = bean.network()
                                port = bean.serverPort
                                port = if (bean is HysteriaBean) {
                                    bean.serverPorts.toHysteriaPort()
                                } else if (bean is Hysteria2Bean) {
                                    bean.serverPorts.toHysteriaPort()
                                } else {
                                    bean.serverPort
                                }
                            })
                        routing.rules.add(RoutingObject.RuleObject().apply {
                            type = "field"
                            inboundTag = listOf(tag)
                            outboundTag = TAG_DIRECT
                        })
                    })

                }

                if (!needGlobal) {
                    outbounds.add(currentOutbound)
                    chainOutbounds.add(currentOutbound)
                    pastExternal = proxyEntity.needExternal()
                    pastOutbound = currentOutbound
                }

            }

            if (isBalancer) {
                val balancerBean = balancer()!!
                val observatory = ObservatoryObject().apply {
                    probeUrl = balancerBean.probeUrl.ifBlank {
                        DataStore.connectionTestURL
                    }
                    if (balancerBean.probeInterval > 0) {
                        probeInterval = "${balancerBean.probeInterval}s"
                    }
                    enableConcurrency = true
                    subjectSelector = HashSet(chainOutbounds.map { it.tag })
                }
                val observatoryItem = MultiObservatoryObject.MultiObservatoryItem().apply {
                    tag = "observer-$tagOutbound"
                    settings = observatory
                }
                if (multiObservatory == null) multiObservatory = MultiObservatoryObject().apply {
                    observers = mutableListOf()
                }
                multiObservatory.observers.add(observatoryItem)

                if (routing.balancers == null) routing.balancers = ArrayList()
                routing.balancers.add(RoutingObject.BalancerObject().apply {
                    tag = "balancer-$tagOutbound"
                    selector = chainOutbounds.map { it.tag }
                    if (multiObservatory == null) {
                        multiObservatory = MultiObservatoryObject().apply {
                            observers = mutableListOf()
                        }
                    }
                    strategy = StrategyObject().apply {
                        type = balancerBean.strategy.takeIf { it.isNotBlank() } ?: "random"
                        when (type) {
                            "leastPing", "leastLoad" -> {
                                settings = StrategyObject.strategyConfig().apply {
                                    observerTag = "observer-$tagOutbound"
                                }
                            }
                            else -> {
                                settings = StrategyObject.strategyConfig().apply {
                                    observerTag = "observer-$tagOutbound"
                                    aliveOnly = true
                                }
                            }
                        }
                    }
                })
                if (tagOutbound == TAG_AGENT) {
                    if (observatoryItem.settings.probeUrl == DataStore.connectionTestURL) {
                        rootObserver = observatoryItem
                    }
                    // if all outbounds of a balancer are dead, the first (default) outbound will be used
                    rootBalancer = RoutingObject.RuleObject().apply {
                        type = "field"
                        network = "tcp,udp"
                        balancerTag = "balancer-$tagOutbound"
                    }
                }
            }

            return chainOutbound

        }

        val mainIsBalancer = proxy.balancerBean != null

        val tagProxy = buildChain(
            TAG_AGENT, proxies, mainIsBalancer
        ) { proxy.balancerBean }

        val balancerMap = mutableMapOf<Long, String>()
        val tagMap = mutableMapOf<Long, String>()
        extraProxies.forEach { (key, entities) ->
            val (id, balancer) = key
            val (isBalancer, balancerBean) = balancer
            tagMap[id] = buildChain("$TAG_AGENT-$id", entities, isBalancer, balancerBean::value)
            if (isBalancer) {
                balancerMap[id] = "balancer-$TAG_AGENT-$id"
            }
        }

        val isVpn = DataStore.serviceMode == Key.MODE_VPN

        for (rule in extraRules) {
            if (rule.packages.isNotEmpty()) {
                dumpUid = true
                if (!isVpn) {
                    alerts.add(Alerts.ROUTE_ALERT_NOT_VPN to rule.displayName())
                    continue
                }
            }
            routing.rules.add(RoutingObject.RuleObject().apply {
                type = "field"
                if (rule.packages.isNotEmpty()) {
                    PackageCache.awaitLoadSync()
                    uidList = rule.packages.map {
                        PackageCache[it]?.takeIf { uid -> uid >= 10000 } ?: 1000
                    }.toHashSet().toList()
                }

                if (rule.ssid.isNotBlank() && Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                    if (app.checkSelfPermission(Manifest.permission.ACCESS_FINE_LOCATION) != PackageManager.PERMISSION_GRANTED) {
                        throw Alerts.RouteAlertException(
                            Alerts.ROUTE_ALERT_NEED_FINE_LOCATION_ACCESS, rule.displayName()
                        )
                    }
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q && app.checkSelfPermission(Manifest.permission.ACCESS_BACKGROUND_LOCATION) != PackageManager.PERMISSION_GRANTED) {
                        throw Alerts.RouteAlertException(
                            Alerts.ROUTE_ALERT_NEED_BACKGROUND_LOCATION_ACCESS, rule.displayName()
                        )
                    }
                    val isLocationEnabled = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                        SagerNet.location.isLocationEnabled
                    } else {
                        try {
                            Settings.Secure.getInt(
                                app.contentResolver, Settings.Secure.LOCATION_MODE
                            ) != Settings.Secure.LOCATION_MODE_OFF
                        } catch (e: Settings.SettingNotFoundException) {
                            e.printStackTrace()
                            false
                        }
                    }
                    if (!isLocationEnabled) {
                        throw Alerts.RouteAlertException(
                            Alerts.ROUTE_ALERT_LOCATION_DISABLED, rule.displayName()
                        )
                    }
                }

                if (rule.domains.isNotBlank()) {
                    domain = rule.domains.listByLineOrComma()
                }
                if (rule.ip.isNotBlank()) {
                    ip = rule.ip.listByLineOrComma()
                }
                if (rule.port.isNotBlank()) {
                    port = rule.port
                }
                if (rule.sourcePort.isNotBlank()) {
                    sourcePort = rule.sourcePort
                }
                if (rule.network.isNotBlank()) {
                    network = rule.network
                }
                if (rule.source.isNotBlank()) {
                    source = rule.source.listByLineOrComma()
                }
                if (rule.protocol.isNotBlank()) {
                    protocol = rule.protocol.listByLineOrComma()
                }
                if (rule.attrs.isNotBlank()) {
                    attrs = rule.attrs
                }
                if (rule.ssid.isNotBlank()) {
                    ssidList = rule.ssid.listByLineOrComma()
                }
                if (rule.networkType.isNotBlank()) {
                    networkType = rule.networkType
                }
                when {
                    rule.reverse -> inboundTag = listOf("reverse-${rule.id}")
                    balancerMap.containsKey(rule.outbound) -> {
                        balancerTag = balancerMap[rule.outbound]
                    }
                    mainIsBalancer && rule.outbound == 0L -> balancerTag = "balancer-$TAG_AGENT"
                    else -> {
                        outboundTag = when (val outId = rule.outbound) {
                            0L -> tagProxy
                            -1L -> TAG_BYPASS
                            -2L -> TAG_BLOCK
                            else -> if (outId == proxy.id) tagProxy else tagMap[outId]
                        }
                    }
                }
            })

            if (rule.reverse) {
                outbounds.add(OutboundObject().apply {
                    tag = "reverse-out-${rule.id}"
                    protocol = "freedom"
                    settings = LazyOutboundConfigurationObject(this,
                        FreedomOutboundConfigurationObject().apply {
                            redirect = rule.redirect
                        })
                })
                if (reverse == null) {
                    reverse = ReverseObject().apply {
                        bridges = ArrayList()
                    }
                }
                reverse.bridges.add(ReverseObject.BridgeObject().apply {
                    tag = "reverse-${rule.id}"
                    domain = rule.domains.substringAfter("full:")
                })
                routing.rules.add(RoutingObject.RuleObject().apply {
                    type = "field"
                    inboundTag = listOf("reverse-${rule.id}")
                    outboundTag = "reverse-out-${rule.id}"
                })
            }

        }

        if (requireWs) {
            browserForwarder = BrowserForwarderObject().apply {
                listenAddr = LOCALHOST
                listenPort = mkPort()
            }
        }

        if (requireSh) {
            browserDialer = BrowserDialerObject().apply {
                listenAddr = LOCALHOST
                listenPort = mkPort()
            }
        }

        outbounds.add(OutboundObject().apply {
            tag = TAG_DIRECT
            protocol = "freedom"
        })
        outbounds.add(OutboundObject().apply {
            tag = TAG_BYPASS
            protocol = "freedom"
            if (DataStore.enableFragment && DataStore.enableFragmentForDirect) {
                streamSettings = StreamSettingsObject().apply {
                    sockopt = StreamSettingsObject.SockoptObject().apply {
                        fragment = StreamSettingsObject.SockoptObject.FragmentObject().apply {
                            packets = "tlshello"
                            length = DataStore.fragmentLength
                            interval = DataStore.fragmentInterval
                        }
                    }
                }
            }
            if (DataStore.resolveDestinationForDirect) {
                settings = LazyOutboundConfigurationObject(this,
                    FreedomOutboundConfigurationObject().apply {
                        domainStrategy = when (ipv6Mode) {
                            IPv6Mode.DISABLE -> "UseIPv4"
                            IPv6Mode.PREFER -> "PreferIPv6"
                            IPv6Mode.ONLY -> "UseIPv6"
                            else -> "PreferIPv4"
                        }
                    }
                )
            }
        })

        outbounds.add(OutboundObject().apply {
            tag = TAG_BLOCK
            protocol = "blackhole"
            /* settings = LazyOutboundConfigurationObject(this,
                 BlackholeOutboundConfigurationObject().apply {
                     keepConnection = true
                 })*/
        })

        if (!forTest) {
            inbounds.add(InboundObject().apply {
                tag = TAG_DNS_IN
                listen = bind
                port = DataStore.localDNSPort
                protocol = "dokodemo-door"
                settings = LazyInboundConfigurationObject(this,
                    DokodemoDoorInboundConfigurationObject().apply {
                        address = "1.0.0.1" // FIXME
                        network = "tcp,udp"
                        port = 53
                    })

            })
        }

        outbounds.add(OutboundObject().apply {
            protocol = "dns"
            tag = TAG_DNS_OUT
            settings = LazyOutboundConfigurationObject(this,
                DNSOutboundConfigurationObject().apply {
                    userLevel = 1
                    address = "1.0.0.1" // FIXME
                    port = 53
                    var dns = remoteDns.first()
                    if (!dns.contains("://")) dns = "udp://$dns"
                    val uri = Uri.parse(dns)
                    uri.scheme?.also {
                        if (it.startsWith("tcp") || it.startsWith("https") || it.startsWith("tls")) {
                            network = "tcp"
                        }
                        if (it.startsWith("tcp") || it.startsWith("udp")) {
                            address = uri.host
                            if (uri.port > 0) {
                                port = uri.port
                            }
                        }
                    }
                })
            proxySettings = OutboundObject.ProxySettingsObject().apply {
                tag = tagProxy // won't fix: v2ray does not support using a balancer tag here
                transportLayer = true
            }
        })

        val bypassIP = HashSet<String>()
        val bypassDomain = HashSet<String>()
        val bypassDomainSkipFakeDns = HashSet<String>()
        val proxyDomain = HashSet<String>()
        val bootstrapDomain = HashSet<String>()

        (proxies + extraProxies.values.flatten()).forEach { it ->
            val bean = it.requireBean()
            bean.apply {
                if (bean is ConfigBean && bean.type == "v2ray_outbound") {
                    // too dirty to read server addresses from a custom outbound config
                    // let users provide them manually
                    bean.serverAddresses.listByLineOrComma().forEach {
                        when {
                            it.isBlank() -> {}
                            it.isIpAddress() -> {
                                bypassIP.add(it)
                            }
                            else -> {
                                bypassDomainSkipFakeDns.add("full:$it")
                            }
                        }
                    }
                } else {
                    if (!serverAddress.isIpAddress()) {
                        bypassDomainSkipFakeDns.add("full:$serverAddress")
                    } else {
                        bypassIP.add(serverAddress)
                    }
                }

            }
        }

        if (bypassIP.isNotEmpty()) {
            routing.rules.add(0, RoutingObject.RuleObject().apply {
                type = "field"
                ip = bypassIP.toList()
                if (DataStore.domainStrategy != "AsIs") {
                    skipDomain = true
                }
                outboundTag = TAG_DIRECT
            })
        }

        if (enableDnsRouting) {
            for (bypassRule in extraRules.filter { it.isBypassRule() }) {
                if (bypassRule.domains.isNotBlank()) {
                    bypassDomain.addAll(bypassRule.domains.listByLineOrComma())
                }
            }
            for (proxyRule in extraRules.filter { it.isProxyRule() }) {
                if (proxyRule.domains.isNotBlank()) {
                    proxyDomain.addAll(proxyRule.domains.listByLineOrComma())
                }
            }
        }

        remoteDns.forEach { dns ->
            Uri.parse(dns).host?.takeIf { !it.isIpAddress() }?.also {
                bypassDomainSkipFakeDns.add("full:$it")
            }
            if (!dns.contains("://") && !dns.isIpAddress() && dns != "localhost") {
                bypassDomainSkipFakeDns.add("full:$dns")
            }
        }

        directDNS.forEach { dns ->
            Uri.parse(dns).host?.takeIf { !it.isIpAddress() }?.also {
                bootstrapDomain.add("full:$it")
            }
            if (!dns.contains("://") && !dns.isIpAddress() && dns != "localhost") {
                bootstrapDomain.add("full:$dns")
            }
        }

        var hasDnsTagDirect = false
        if (bypassDomain.isNotEmpty()) {
            dns.servers.addAll(remoteDns.map {
                DnsObject.StringOrServerObject().apply {
                    valueY = DnsObject.ServerObject().apply {
                        address = it
                        domains = proxyDomain.toList() // v2fly/v2ray-core#1558, v2fly/v2ray-core#1855
                        queryStrategy = remoteDnsQueryStrategy
                        if (DataStore.ednsClientIp.isNotBlank()) {
                            clientIp = DataStore.ednsClientIp
                        }
                        if (useFakeDns) {
                            fakedns = mutableListOf()
                            if (queryStrategy != "UseIPv6") {
                                fakedns.add(DnsObject.ServerObject.StringOrFakeDnsObject().apply {
                                    valueY = FakeDnsObject().apply {
                                        ipPool = "${VpnService.FAKEDNS_VLAN4_CLIENT}/15"
                                        poolSize = 65535
                                    }
                                })
                            }
                            if (queryStrategy != "UseIPv4") {
                                fakedns.add(DnsObject.ServerObject.StringOrFakeDnsObject().apply {
                                    valueY = FakeDnsObject().apply {
                                        ipPool = "${VpnService.FAKEDNS_VLAN6_CLIENT}/18"
                                        poolSize = 65535
                                    }
                                })
                            }
                        }
                    }
                }
            })
            if (bootstrapDomain.isNotEmpty()) {
                dns.servers.addAll(bootstrapDNS.map {
                    DnsObject.StringOrServerObject().apply {
                        valueY = DnsObject.ServerObject().apply {
                            address = it
                            domains = bootstrapDomain.toList() // v2fly/v2ray-core#1558, v2fly/v2ray-core#1855
                            queryStrategy = directDnsQueryStrategy
                            if (!it.contains("+local://") && it != "localhost") {
                                tag = TAG_DNS_DIRECT
                                hasDnsTagDirect = true
                            }
                        }
                    }
                })
            }
            if (bypassDomainSkipFakeDns.isNotEmpty()) {
                dns.servers.addAll(directDNS.map {
                    DnsObject.StringOrServerObject().apply {
                        valueY = DnsObject.ServerObject().apply {
                            address = it
                            // skip fake DNS for server addresses and DNS server addresses
                            domains = bypassDomainSkipFakeDns.toList()
                            queryStrategy = directDnsQueryStrategy
                            if (!it.contains("+local://") && it != "localhost") {
                                tag = TAG_DNS_DIRECT
                                hasDnsTagDirect = true
                            }
                            fallbackStrategy = "disabled"
                        }
                    }
                })
            }
            if (bypassDomain.isNotEmpty()) {
                dns.servers.addAll(directDNS.map {
                    DnsObject.StringOrServerObject().apply {
                        valueY = DnsObject.ServerObject().apply {
                            address = it
                            //FIXME: This relies on the behavior of a bug.
                            domains = bypassDomain.toList() // v2fly/v2ray-core#1558, v2fly/v2ray-core#1855
                            queryStrategy = directDnsQueryStrategy
                            if (!it.contains("+local://") && it != "localhost") {
                                tag = TAG_DNS_DIRECT
                                hasDnsTagDirect = true
                            }
                            if (useFakeDns) {
                                fakedns = mutableListOf()
                                if (queryStrategy != "UseIPv6") {
                                    fakedns.add(DnsObject.ServerObject.StringOrFakeDnsObject().apply {
                                        valueY = FakeDnsObject().apply {
                                            ipPool = "${VpnService.FAKEDNS_VLAN4_CLIENT}/15"
                                            poolSize = 65535
                                        }
                                    })
                                }
                                if (queryStrategy != "UseIPv4") {
                                    fakedns.add(DnsObject.ServerObject.StringOrFakeDnsObject().apply {
                                        valueY = FakeDnsObject().apply {
                                            ipPool = "${VpnService.FAKEDNS_VLAN6_CLIENT}/18"
                                            poolSize = 65535
                                        }
                                    })
                                }
                            }
                            fallbackStrategy = "disabled"
                        }
                    }
                })
            }
        } else {
            dns.servers.addAll(remoteDns.map {
                DnsObject.StringOrServerObject().apply {
                    valueY = DnsObject.ServerObject().apply {
                        address = it
                        queryStrategy = remoteDnsQueryStrategy
                        if (DataStore.ednsClientIp.isNotBlank()) {
                            clientIp = DataStore.ednsClientIp
                        }
                        if (useFakeDns) {
                            fakedns = mutableListOf()
                            if (queryStrategy != "UseIPv6") {
                                fakedns.add(DnsObject.ServerObject.StringOrFakeDnsObject().apply {
                                    valueY = FakeDnsObject().apply {
                                        ipPool = "${VpnService.FAKEDNS_VLAN4_CLIENT}/15"
                                        poolSize = 65535
                                    }
                                })
                            }
                            if (queryStrategy != "UseIPv4") {
                                fakedns.add(DnsObject.ServerObject.StringOrFakeDnsObject().apply {
                                    valueY = FakeDnsObject().apply {
                                        ipPool = "${VpnService.FAKEDNS_VLAN6_CLIENT}/18"
                                        poolSize = 65535
                                    }
                                })
                            }
                        }
                    }
                }
            })
        }

        if (!forTest && hasDnsTagDirect) {
            routing.rules.add(0, RoutingObject.RuleObject().apply {
                type = "field"
                inboundTag = listOf(TAG_DNS_DIRECT)
                outboundTag = TAG_BYPASS
            })
        }

        if (!forTest && !hijackDns) {
            routing.rules.add(0, RoutingObject.RuleObject().apply {
                type = "field"
                protocol = listOf("dns")
                outboundTag = TAG_DNS_OUT
            })
        }

        if (!forTest) {
            routing.rules.add(0, RoutingObject.RuleObject().apply {
                type = "field"
                inboundTag = listOf(TAG_DNS_IN)
                outboundTag = TAG_DNS_OUT
            })
        }

        if (rootBalancer != null) routing.rules.add(rootBalancer)

        if (!forTest && DataStore.bypassLan && (requireHttp || DataStore.bypassLanInCoreOnly)) {
            routing.rules.add(RoutingObject.RuleObject().apply {
                type = "field"
                outboundTag = TAG_BYPASS
                ip = listOf("geoip:private")
            })
        }

        if (trafficStatistics) stats = emptyMap()

        result = V2rayBuildResult(
            gson.toJson(this),
            indexMap,
            requireWs,
            if (requireWs) browserForwarder.listenPort else 0,
            requireSh,
            if (requireSh) browserDialer.listenPort else 0,
            outboundTags,
            outboundTagsCurrent,
            outboundTagsAll,
            TAG_BYPASS,
            rootObserver?.tag ?: "",
            rootObserver?.settings?.subjectSelector ?: HashSet(),
            dumpUid,
            alerts
        )
    }

    return result

}

fun buildCustomConfig(proxy: ProxyEntity, port: Int): V2rayBuildResult {

    val bind = LOCALHOST
    val trafficSniffing = DataStore.trafficSniffing

    val bean = proxy.configBean!!
    val config = JSONObject(bean.content)
    val inbounds = config.getJSONArray("inbounds")
        ?.filterIsInstance<JSONObject>()
        ?.map { gson.fromJson(it.toString(), InboundObject::class.java) }
        ?.toMutableList() ?: ArrayList()

    var socksInbound = inbounds.find { it.tag == TAG_SOCKS }?.apply {
        if (protocol != "socks") error("Inbound $tag with type $protocol, excepted socks.")
    }

    if (socksInbound == null) {
        val socksInbounds = inbounds.filter { it.protocol == "socks" }
        if (socksInbounds.size == 1) {
            socksInbound = socksInbounds[0]
        }
    }

    if (socksInbound != null) {
        socksInbound.apply {
            listen = bind
            this.port = port
        }
    } else {
        inbounds.add(InboundObject().apply {
            tag = TAG_SOCKS
            listen = bind
            this.port = port
            protocol = "socks"
            settings = LazyInboundConfigurationObject(this,
                SocksInboundConfigurationObject().apply {
                    auth = "noauth"
                    udp = true
                })
            if (trafficSniffing) {
                sniffing = InboundObject.SniffingObject().apply {
                    enabled = true
                    destOverride = listOf("http", "tls", "quic")
                    metadataOnly = false
                }
            }
        })
    }

    var requireWs = false
    var wsPort = 0
    if (config.containsKey("browserForwarder")) {
        config["browserForwarder"] = JSONObject(gson.toJson(BrowserForwarderObject().apply {
            requireWs = true
            listenAddr = LOCALHOST
            listenPort = mkPort()
            wsPort = listenPort
        }))
    }

    var requireSh = false
    var shPort = 0
    if (config.containsKey("browserDialer")) {
        config["browserDialer"] = JSONObject(gson.toJson(BrowserDialerObject().apply {
            requireSh = true
            listenAddr = LOCALHOST
            listenPort = mkPort()
            shPort = listenPort
        }))
    }

    val outbounds = try {
        config.getJSONArray("outbounds")?.filterIsInstance<JSONObject>()?.map { it ->
            gson.fromJson(it.toString().takeIf { it.isNotBlank() } ?: "{}",
                OutboundObject::class.java)
        }?.toMutableList()
    } catch (e: JsonSyntaxException) {
        null
    }
    var flushOutbounds = false

    val outboundTags = ArrayList<String>()
    val firstOutbound = outbounds?.get(0)
    if (firstOutbound != null) {
        if (firstOutbound.tag == null) {
            firstOutbound.tag = TAG_AGENT
            outboundTags.add(TAG_AGENT)
            flushOutbounds = true
        } else {
            outboundTags.add(firstOutbound.tag)
        }
    }

    var directTag = ""
    val directOutbounds = outbounds?.filter { it.protocol == "freedom" }
    if (!directOutbounds.isNullOrEmpty()) {
        val directOutbound = if (directOutbounds.size == 1) {
            directOutbounds[0]
        } else {
            val directOutboundsWithTag = directOutbounds.filter { it.tag != null }
            if (directOutboundsWithTag.isNotEmpty()) {
                directOutboundsWithTag[0]
            } else {
                directOutbounds[0]
            }
        }
        if (directOutbound.tag.isNullOrBlank()) {
            directOutbound.tag = TAG_DIRECT
            flushOutbounds = true
        }
        directTag = directOutbound.tag
    }

    inbounds.forEach { it.init() }
    config["inbounds"] = JSONArray(inbounds.map { JSONObject(gson.toJson(it)) })
    if (flushOutbounds) {
        outbounds!!.forEach { it.init() }
        config["outbounds"] = JSONArray(outbounds.map { JSONObject(gson.toJson(it)) })
    }


    return V2rayBuildResult(
        config.toStringPretty(),
        emptyList(),
        requireWs,
        wsPort,
        requireSh,
        shPort,
        outboundTags,
        outboundTags,
        emptyMap(),
        directTag,
        "",
        emptySet(),
        false,
        emptyList()
    )

}