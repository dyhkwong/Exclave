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

package io.nekohasekai.sagernet.group

import androidx.core.net.toUri
import cn.hutool.core.codec.Base64
import cn.hutool.core.lang.UUID
import cn.hutool.json.JSONObject
import cn.hutool.json.JSONUtil
import com.github.shadowsocks.plugin.PluginOptions
import io.nekohasekai.sagernet.R
import io.nekohasekai.sagernet.SagerNet
import io.nekohasekai.sagernet.database.DataStore
import io.nekohasekai.sagernet.database.GroupManager
import io.nekohasekai.sagernet.database.ProxyEntity
import io.nekohasekai.sagernet.database.ProxyGroup
import io.nekohasekai.sagernet.database.SagerDatabase
import io.nekohasekai.sagernet.database.SubscriptionBean
import io.nekohasekai.sagernet.fmt.AbstractBean
import io.nekohasekai.sagernet.fmt.anytls.AnyTLSBean
import io.nekohasekai.sagernet.fmt.http.HttpBean
import io.nekohasekai.sagernet.fmt.http3.Http3Bean
import io.nekohasekai.sagernet.fmt.hysteria.HysteriaBean
import io.nekohasekai.sagernet.fmt.hysteria2.Hysteria2Bean
import io.nekohasekai.sagernet.fmt.mieru.MieruBean
import io.nekohasekai.sagernet.fmt.shadowsocks.parseShadowsocksConfig
import io.nekohasekai.sagernet.fmt.shadowsocks.ShadowsocksBean
import io.nekohasekai.sagernet.fmt.shadowsocks.fixInvalidParams
import io.nekohasekai.sagernet.fmt.shadowsocks.supportedShadowsocks2022Method
import io.nekohasekai.sagernet.fmt.shadowsocks.supportedShadowsocksMethod
import io.nekohasekai.sagernet.fmt.shadowsocksr.ShadowsocksRBean
import io.nekohasekai.sagernet.fmt.shadowsocksr.supportedShadowsocksRMethod
import io.nekohasekai.sagernet.fmt.shadowsocksr.supportedShadowsocksRObfs
import io.nekohasekai.sagernet.fmt.shadowsocksr.supportedShadowsocksRProtocol
import io.nekohasekai.sagernet.fmt.socks.SOCKSBean
import io.nekohasekai.sagernet.fmt.ssh.SSHBean
import io.nekohasekai.sagernet.fmt.trojan.TrojanBean
import io.nekohasekai.sagernet.fmt.tuic.TuicBean
import io.nekohasekai.sagernet.fmt.tuic.supportedTuicCongestionControl
import io.nekohasekai.sagernet.fmt.tuic.supportedTuicRelayMode
import io.nekohasekai.sagernet.fmt.tuic5.Tuic5Bean
import io.nekohasekai.sagernet.fmt.tuic5.supportedTuic5CongestionControl
import io.nekohasekai.sagernet.fmt.tuic5.supportedTuic5RelayMode
import io.nekohasekai.sagernet.fmt.v2ray.VLESSBean
import io.nekohasekai.sagernet.fmt.v2ray.VMessBean
import io.nekohasekai.sagernet.fmt.v2ray.legacyVlessFlow
import io.nekohasekai.sagernet.fmt.v2ray.nonRawTransportName
import io.nekohasekai.sagernet.fmt.v2ray.supportedKcpQuicHeaderType
import io.nekohasekai.sagernet.fmt.v2ray.supportedQuicSecurity
import io.nekohasekai.sagernet.fmt.v2ray.supportedVlessFlow
import io.nekohasekai.sagernet.fmt.v2ray.supportedVmessMethod
import io.nekohasekai.sagernet.fmt.v2ray.supportedXhttpMode
import io.nekohasekai.sagernet.fmt.wireguard.parseWireGuardConfig
import io.nekohasekai.sagernet.fmt.wireguard.WireGuardBean
import io.nekohasekai.sagernet.ktx.decodeBase64UrlSafe
import io.nekohasekai.sagernet.ktx.parseShareLinks
import io.nekohasekai.sagernet.ktx.*
import kotlin.time.Duration
import kotlin.time.DurationUnit
import libcore.Libcore
import org.yaml.snakeyaml.TypeDescription
import org.yaml.snakeyaml.Yaml

@Suppress("EXPERIMENTAL_API_USAGE")
object RawUpdater : GroupUpdater() {

    override suspend fun doUpdate(
        proxyGroup: ProxyGroup,
        subscription: SubscriptionBean,
        userInterface: GroupManager.Interface?,
        byUser: Boolean
    ) {

        val link = subscription.link
        var proxies: List<AbstractBean>
        if (link.startsWith("content://")) {
            val contentText = app.contentResolver.openInputStream(link.toUri())
                ?.bufferedReader()
                ?.readText()

            proxies = contentText?.let { parseRaw(contentText) }
                ?: error(app.getString(R.string.no_proxies_found_in_subscription))
        } else {
            val response = Libcore.newHttpClient().apply {
                if (SagerNet.started && DataStore.startedProfile > 0) {
                    useSocks5(DataStore.socksPort)
                }
            }.newRequest().apply {
                setURL(subscription.link)
                if (subscription.customUserAgent.isNotEmpty()) {
                    setUserAgent(subscription.customUserAgent)
                } else {
                    setUserAgent(USER_AGENT)
                }
            }.execute()

            proxies = parseRaw(response.contentString)
                ?: error(app.getString(R.string.no_proxies_found))

            val subscriptionUserinfo = response.getHeader("Subscription-Userinfo")
            if (subscriptionUserinfo.isNotEmpty()) {
                fun get(regex: String): String? {
                    return regex.toRegex().findAll(subscriptionUserinfo).mapNotNull {
                        if (it.groupValues.size > 1) it.groupValues[1] else null
                    }.firstOrNull()
                }
                var used = 0L
                try {
                    val upload = get("upload=([0-9]+)")?.toLong() ?: -1L
                    if (upload > 0L) {
                        used += upload
                    }
                    val download = get("download=([0-9]+)")?.toLong() ?: -1L
                    if (download > 0L) {
                        used += download
                    }
                    val total = get("total=([0-9]+)")?.toLong() ?: -1L
                    subscription.apply {
                        if (upload > 0L || download > 0L) {
                            bytesUsed = used
                            bytesRemaining = if (total > 0L) total - used else -1L
                        } else {
                            bytesUsed = -1L
                            bytesRemaining = -1L
                        }
                        expiryDate = get("expire=([0-9]+)")?.toLong() ?: -1L
                    }
                } catch (_: Exception) {
                }
            } else {
                subscription.apply {
                    bytesUsed = -1L
                    bytesRemaining = -1L
                    expiryDate = -1L
                }
            }
        }

        if (subscription.nameFilter.isNotEmpty()) {
            val pattern = Regex(subscription.nameFilter)
            proxies = proxies.filter { !pattern.containsMatchIn(it.name) }
        }

        proxies.forEach { it.applyDefaultValues() }

        val proxiesMap = LinkedHashMap<String, AbstractBean>()
        for (proxy in proxies) {
            var index = 0
            var name = proxy.displayName()
            while (proxiesMap.containsKey(name)) {
                println("Exists name: $name")
                index++
                name = name.replace(" (${index - 1})", "")
                name = "$name ($index)"
                proxy.name = name
            }
            proxiesMap[proxy.displayName()] = proxy
        }
        proxies = proxiesMap.values.toList()

        val exists = SagerDatabase.proxyDao.getByGroup(proxyGroup.id)
        val duplicate = ArrayList<String>()
        if (subscription.deduplication) {
            Logs.d("Before deduplication: ${proxies.size}")
            val uniqueProxies = LinkedHashSet<Protocols.Deduplication>()
            val uniqueNames = HashMap<Protocols.Deduplication, String>()
            for (p in proxies) {
                val proxy = Protocols.Deduplication(p, p.javaClass.toString())
                if (!uniqueProxies.add(proxy)) {
                    val index = uniqueProxies.indexOf(proxy)
                    if (uniqueNames.containsKey(proxy)) {
                        val name = uniqueNames[proxy]!!.replace(" ($index)", "")
                        if (name.isNotEmpty()) {
                            duplicate.add("$name ($index)")
                            uniqueNames[proxy] = ""
                        }
                    }
                    duplicate.add(p.displayName() + " ($index)")
                } else {
                    uniqueNames[proxy] = p.displayName()
                }
            }
            uniqueProxies.retainAll(uniqueNames.keys)
            proxies = uniqueProxies.toList().map { it.bean }
        }

        Logs.d("New profiles: ${proxies.size}")

        val nameMap = proxies.associateBy { bean ->
            bean.displayName()
        }

        Logs.d("Unique profiles: ${nameMap.size}")

        val toDelete = ArrayList<ProxyEntity>()
        val toReplace = exists.mapNotNull { entity ->
            val name = entity.displayName()
            if (nameMap.contains(name)) name to entity else let {
                toDelete.add(entity)
                null
            }
        }.toMap()

        Logs.d("toDelete profiles: ${toDelete.size}")
        Logs.d("toReplace profiles: ${toReplace.size}")

        val toUpdate = ArrayList<ProxyEntity>()
        val added = mutableListOf<String>()
        val updated = mutableMapOf<String, String>()
        val deleted = toDelete.map { it.displayName() }

        var userOrder = 1L
        var changed = toDelete.size
        for ((name, bean) in nameMap.entries) {
            if (toReplace.contains(name)) {
                val entity = toReplace[name]!!
                val existsBean = entity.requireBean()
                existsBean.applyFeatureSettings(bean)
                when {
                    existsBean != bean -> {
                        changed++
                        entity.putBean(bean)
                        toUpdate.add(entity)
                        updated[entity.displayName()] = name

                        Logs.d("Updated profile: $name")
                    }
                    entity.userOrder != userOrder -> {
                        entity.putBean(bean)
                        toUpdate.add(entity)
                        entity.userOrder = userOrder

                        Logs.d("Reordered profile: $name")
                    }
                    else -> {
                        Logs.d("Ignored profile: $name")
                    }
                }
            } else {
                changed++
                SagerDatabase.proxyDao.addProxy(ProxyEntity(
                    groupId = proxyGroup.id, userOrder = userOrder
                ).apply {
                    putBean(bean)
                })
                added.add(name)
                Logs.d("Inserted profile: $name")
            }
            userOrder++
        }

        SagerDatabase.proxyDao.updateProxy(toUpdate).also {
            Logs.d("Updated profiles: $it")
        }

        SagerDatabase.proxyDao.deleteProxy(toDelete).also {
            Logs.d("Deleted profiles: $it")
        }

        val existCount = SagerDatabase.proxyDao.countByGroup(proxyGroup.id).toInt()

        if (existCount != proxies.size) {
            Logs.e("Exist profiles: $existCount, new profiles: ${proxies.size}")
        }

        subscription.lastUpdated = System.currentTimeMillis() / 1000
        SagerDatabase.groupDao.updateGroup(proxyGroup)
        finishUpdate(proxyGroup)

        userInterface?.onUpdateSuccess(
            proxyGroup, changed, added, updated, deleted, duplicate, byUser
        )
    }

    @Suppress("UNCHECKED_CAST")
    fun parseRaw(text: String): List<AbstractBean>? {
        if (text.contains("proxies")) {
            try {
                (Yaml().apply {
                    addTypeDescription(TypeDescription(String::class.java, "str"))
                }.loadAs(text, Map::class.java)["proxies"] as? List<Map<String, Any?>>)?.let { proxies ->
                    val beans = mutableListOf<AbstractBean>()
                    proxies.forEach {
                        beans.addAll(parseClashProxies(it))
                    }
                    return beans.takeIf { it.isNotEmpty() }
                }
            } catch (_: Exception) {}
        }
        if (text.contains("[Interface]")) {
            try {
                parseWireGuardConfig(text).takeIf { it.isNotEmpty() }?.let {
                    return it
                }
            } catch (_: Exception) {}
        }
        try {
            JSONUtil.parse(Libcore.stripJSON(text))?.let { json ->
                if (json !is JSONObject) return null
                return parseJSONConfig(json).takeIf { it.isNotEmpty() }
            }
        } catch (_: Exception) {}
        try {
            parseShareLinks(text.decodeBase64UrlSafe()).takeIf { it.isNotEmpty() }?.let {
                return it
            }
        } catch (e: SubscriptionFoundException) {
            throw(e)
        } catch (_: Exception) {}
        try {
            parseShareLinks(text).takeIf { it.isNotEmpty() }?.let {
                return it
            }
        } catch (e: SubscriptionFoundException) {
            throw(e)
        } catch (_: Exception) {}
        return null
    }

    @Suppress("UNCHECKED_CAST")
    private fun parseJSONConfig(json: JSONObject): List<AbstractBean> {
        when {
            json.getInt("version") != null && json.containsKey("servers") -> {
                val beans = ArrayList<ShadowsocksBean>()
                (json.getJSONArray("servers") as? List<JSONObject>)?.forEach { server ->
                    server.parseShadowsocksConfig()?.let {
                        beans.add(it)
                    }
                }
                return beans
            }
            json.containsKey("method") -> {
                json.parseShadowsocksConfig()?.let {
                    return listOf(it)
                } ?: return ArrayList()
            }
            json.contains("type") -> {
                return parseSingBoxEndpoint(json).takeIf { it.isNotEmpty() }
                    ?: parseSingBoxOutbound(json)
            }
            json.contains("protocol") -> {
                return parseV2ray5Outbound(json).takeIf { it.isNotEmpty() }
                    ?: parseV2RayOutbound(json)
            }
            else -> {
                val beans = ArrayList<AbstractBean>()
                json.getArray("endpoints")?.filterIsInstance<JSONObject>()?.forEach { endpoint ->
                    beans.addAll(parseSingBoxEndpoint(endpoint))
                }
                json.getArray("outbounds")?.filterIsInstance<JSONObject>()?.forEach { outbound ->
                    when {
                        outbound.contains("protocol") -> {
                            beans.addAll(
                                parseV2ray5Outbound(outbound).takeIf { it.isNotEmpty() } ?:
                                parseV2RayOutbound(outbound)
                            )
                        }
                        outbound.contains("type") -> {
                            beans.addAll(parseSingBoxOutbound(outbound))
                        }
                    }
                }
                return beans
            }
        }
    }

    @Suppress("UNCHECKED_CAST")
    private fun parseV2RayOutbound(outbound: JSONObject): List<AbstractBean> {
        // v2ray JSONv4 config, Xray config and JSONv4 config of Exclave's v2ray fork only
        val proxies = ArrayList<AbstractBean>()
        when (val proto = outbound.getString("protocol")?.lowercase()) {
            "vmess", "vless", "trojan", "shadowsocks", "socks", "http", "shadowsocks2022", "shadowsocks-2022" -> {
                val v2rayBean = when (proto) {
                    "vmess" -> VMessBean()
                    "vless" -> VLESSBean()
                    "trojan" -> TrojanBean()
                    "shadowsocks", "shadowsocks2022", "shadowsocks-2022" -> ShadowsocksBean()
                    "socks" -> SOCKSBean()
                    else -> HttpBean()
                }
                outbound.getObject("streamSettings")?.also { streamSettings ->
                    streamSettings.getString("security")?.lowercase()?.also { security ->
                        when (security) {
                            "tls", "utls", "xtls" -> {
                                v2rayBean.security = "tls"
                                var tlsConfig = streamSettings.getObject("tlsSettings")
                                if (security == "utls") {
                                    streamSettings.getObject("utlsSettings")?.also {
                                        tlsConfig = it.getObject("tlsConfig")
                                    }
                                }
                                if (security == "xtls") { // old Xray
                                    streamSettings.getObject("xtlsSettings")?.also {
                                        tlsConfig = it
                                    }
                                }
                                tlsConfig?.also { tlsSettings ->
                                    tlsSettings.getString("serverName")?.also {
                                        v2rayBean.sni = it
                                    }
                                    (tlsSettings.getAny("alpn") as? List<String>)?.also {
                                        v2rayBean.alpn = it.joinToString("\n")
                                    } ?: tlsSettings.getString("alpn")?.also {
                                        v2rayBean.alpn = it.split(",").joinToString("\n")
                                    }
                                    tlsSettings.getBoolean("allowInsecure")?.also {
                                        v2rayBean.allowInsecure = it
                                    }
                                    (tlsSettings.getObject("pinnedPeerCertificateChainSha256") as? List<String>)?.also {
                                        v2rayBean.pinnedPeerCertificateChainSha256 = it.joinToString("\n")
                                        tlsSettings.getBoolean("allowInsecureIfPinnedPeerCertificate")?.also { allowInsecure ->
                                            v2rayBean.allowInsecure = allowInsecure
                                        }
                                    }
                                    // tlsSettings.getString("imitate")
                                    // tlsSettings.getString("fingerprint")
                                }
                            }
                            "reality" -> {
                                v2rayBean.security = "reality"
                                streamSettings.getObject("realitySettings")?.also { realitySettings ->
                                    realitySettings.getString("serverName")?.also {
                                        v2rayBean.sni = it
                                    }
                                    realitySettings.getString("publicKey")?.also {
                                        v2rayBean.realityPublicKey = it
                                    }
                                    realitySettings.getString("shortId")?.also {
                                        v2rayBean.realityShortId = it
                                    }
                                    // realitySettings.getString("fingerprint")
                                }
                            }
                        }
                    }
                    streamSettings.getString("network")?.lowercase()?.also { network ->
                        when (network) {
                            "tcp", "raw" -> {
                                v2rayBean.type = "tcp"
                                (streamSettings.getObject("tcpSettings") ?: streamSettings.getObject("rawSettings"))?.also { tcpSettings ->
                                    tcpSettings.getObject("header")?.also { header ->
                                        when (header.getString("type")?.lowercase()) {
                                            "none" -> {}
                                            "http" -> {
                                                v2rayBean.headerType = "http"
                                                header.getObject("request")?.also { request ->
                                                    (request.getAny("path") as? List<String>)?.also {
                                                        v2rayBean.path = it.joinToString("\n")
                                                    } ?: request.getString("path")?.also {
                                                        v2rayBean.path = it.split(",").joinToString("\n")
                                                    }
                                                    request.getObject("headers")?.also { headers ->
                                                        (headers.getAny("Host") as? List<String>)?.also {
                                                            v2rayBean.host = it.joinToString("\n")
                                                        } ?: headers.getString("Host")?.also {
                                                            v2rayBean.host = it.split(",").joinToString("\n")
                                                        }
                                                    }
                                                }
                                            }
                                            else -> return proxies
                                        }
                                    }
                                }
                            }
                            "kcp", "mkcp" -> {
                                v2rayBean.type = "kcp"
                                streamSettings.getObject("kcpSettings")?.also { kcpSettings ->
                                    kcpSettings.getString("seed")?.also {
                                        v2rayBean.mKcpSeed = it
                                    }
                                    kcpSettings.getObject("header")?.also { header ->
                                        header.getString("type")?.lowercase()?.also {
                                            if (it !in supportedKcpQuicHeaderType) return proxies
                                            v2rayBean.headerType = it
                                        }
                                    }
                                }
                            }
                            "ws", "websocket" -> {
                                v2rayBean.type = "ws"
                                streamSettings.getObject("wsSettings")?.also { wsSettings ->
                                    (wsSettings.getAny("headers") as? Map<String, String>)?.forEach { (key, value) ->
                                        when (key.lowercase()) {
                                            "host" -> {
                                                v2rayBean.host = value
                                            }
                                        }
                                    }
                                    wsSettings.getString("host")?.also {
                                        // Xray has a separate field of Host header
                                        // will not follow the breaking change in
                                        // https://github.com/XTLS/Xray-core/commit/a2b773135a860f63e990874c551b099dfc888471
                                        v2rayBean.host = it
                                    }
                                    wsSettings.getInteger("maxEarlyData")?.also {
                                        v2rayBean.maxEarlyData = it
                                    }
                                    wsSettings.getString("earlyDataHeaderName")?.also {
                                        v2rayBean.earlyDataHeaderName = it
                                    }
                                    wsSettings.getString("path")?.also { path ->
                                        v2rayBean.path = path
                                        // RPRX's smart-assed invention. This of course will break under some conditions.
                                        val u = Libcore.parseURL(path)
                                        u.queryParameter("ed")?.also { ed ->
                                            u.deleteQueryParameter("ed")
                                            v2rayBean.path = u.string
                                            (ed.toIntOrNull())?.also {
                                                v2rayBean.maxEarlyData = it
                                            }
                                            v2rayBean.earlyDataHeaderName = "Sec-WebSocket-Protocol"
                                        }
                                    }
                                }
                            }
                            "http", "h2" -> {
                                v2rayBean.type = "http"
                                streamSettings.getObject("httpSettings")?.also { httpSettings ->
                                    // will not follow the breaking change in
                                    // https://github.com/XTLS/Xray-core/commit/0a252ac15d34e7c23a1d3807a89bfca51cbb559b
                                    (httpSettings.getAny("host") as? List<String>)?.also {
                                        v2rayBean.host = it.joinToString("\n")
                                    } ?: httpSettings.getString("host")?.also {
                                        v2rayBean.host = it.split(",").joinToString("\n")
                                    }
                                    httpSettings.getString("path")?.also {
                                        v2rayBean.path = it
                                    }
                                }
                            }
                            "quic" -> {
                                v2rayBean.type = "quic"
                                streamSettings.getObject("quicSettings")?.also { quicSettings ->
                                    quicSettings.getString("security")?.lowercase()?.also {
                                        if (it !in supportedQuicSecurity) return proxies
                                        v2rayBean.quicSecurity = it
                                    }
                                    quicSettings.getString("key")?.also {
                                        v2rayBean.quicKey = it
                                    }
                                    quicSettings.getObject("header")?.also { header ->
                                        header.getString("type")?.lowercase()?.also {
                                            if (it !in supportedKcpQuicHeaderType) return proxies
                                            v2rayBean.headerType = it
                                        }
                                    }
                                }
                            }
                            "grpc", "gun" -> {
                                v2rayBean.type = "grpc"
                                // Xray hijacks the share link standard, uses escaped `serviceName` and some other non-standard `serviceName`s and breaks the compatibility with other implementations.
                                // Fixing the compatibility with Xray will break the compatibility with V2Ray and others.
                                // So do not fix the compatibility with Xray.
                                (streamSettings.getObject("grpcSettings") ?: streamSettings.getObject("gunSettings"))?.also { grpcSettings ->
                                    grpcSettings.getString("serviceName")?.also {
                                        v2rayBean.grpcServiceName = it
                                    }
                                }
                            }
                            "httpupgrade" -> {
                                v2rayBean.type = "httpupgrade"
                                streamSettings.getObject("httpupgradeSettings")?.also { httpupgradeSettings ->
                                    httpupgradeSettings.getString("host")?.also {
                                        // will not follow the breaking change in
                                        // https://github.com/XTLS/Xray-core/commit/a2b773135a860f63e990874c551b099dfc888471
                                        v2rayBean.host = it
                                    }
                                    httpupgradeSettings.getString("path")?.also {
                                        v2rayBean.path = it
                                        // RPRX's smart-assed invention. This of course will break under some conditions.
                                        val u = Libcore.parseURL(it)
                                        u.queryParameter("ed")?.also {
                                            u.deleteQueryParameter("ed")
                                            v2rayBean.path = u.string
                                        }
                                    }
                                    httpupgradeSettings.getInteger("maxEarlyData")?.also {
                                        v2rayBean.maxEarlyData = it
                                    }
                                    httpupgradeSettings.getString("earlyDataHeaderName")?.also {
                                        v2rayBean.earlyDataHeaderName = it
                                    }
                                }
                            }
                            "meek" -> {
                                v2rayBean.type = "meek"
                                streamSettings.getObject("meekSettings")?.also { meekSettings ->
                                    meekSettings.getString("url")?.also {
                                        v2rayBean.meekUrl = it
                                    }
                                }
                            }
                            "mekya" -> {
                                v2rayBean.type = "mekya"
                                streamSettings.getObject("mekyaSettings")?.also { mekyaSettings ->
                                    mekyaSettings.getString("url")?.also {
                                        v2rayBean.mekyaUrl = it
                                    }
                                    mekyaSettings.getObject("kcp")?.also { kcp ->
                                        kcp.getString("seed")?.also {
                                            v2rayBean.mekyaKcpSeed = it
                                        }
                                        kcp.getObject("header")?.also { header ->
                                            header.getString("type")?.lowercase()?.also {
                                                if (it !in supportedKcpQuicHeaderType) return proxies
                                                v2rayBean.mekyaKcpHeaderType = it
                                            }
                                        }
                                    }
                                }
                            }
                            "splithttp", "xhttp" -> {
                                v2rayBean.type = "splithttp"
                                (streamSettings.getObject("splithttpSettings") ?: streamSettings.getObject("xhttpSettings"))?.also { splithttpSettings ->
                                    splithttpSettings.getString("host")?.also {
                                        v2rayBean.host = it
                                    }
                                    splithttpSettings.getString("path")?.also {
                                        v2rayBean.path = it
                                    }
                                    splithttpSettings.getString("mode")?.also {
                                        v2rayBean.splithttpMode = when (it) {
                                            in supportedXhttpMode -> it
                                            "" -> "auto"
                                            else -> return proxies
                                        }
                                    }
                                    // fuck RPRX `extra`
                                    var extra = JSONObject()
                                    splithttpSettings.getObject("extra")?.also {
                                        extra = it
                                    }
                                    if (!extra.contains("scMaxEachPostBytes")) {
                                        splithttpSettings.getInteger("scMaxEachPostBytes")?.also {
                                            extra.set("scMaxEachPostBytes", it)
                                        } ?: splithttpSettings.getString("scMaxEachPostBytes")?.also {
                                            extra.set("scMaxEachPostBytes", it)
                                        }
                                    }
                                    if (!extra.contains("scMinPostsIntervalMs")) {
                                        splithttpSettings.getInteger("scMinPostsIntervalMs")?.also {
                                            extra.set("scMinPostsIntervalMs", it)
                                        } ?: splithttpSettings.getString("scMinPostsIntervalMs")?.also {
                                            extra.set("scMinPostsIntervalMs", it)
                                        }
                                    }
                                    if (!extra.contains("xPaddingBytes")) {
                                        splithttpSettings.getInteger("xPaddingBytes")?.also {
                                            extra.set("xPaddingBytes", it)
                                        } ?: splithttpSettings.getString("xPaddingBytes")?.also {
                                            extra.set("xPaddingBytes", it)
                                        }
                                    }
                                    if (!extra.contains("noGRPCHeader")) {
                                        splithttpSettings.getBoolean("noGRPCHeader")?.also {
                                            extra.set("noGRPCHeader", it)
                                        }
                                    }
                                    if (!extra.isEmpty()) {
                                        v2rayBean.splithttpExtra = extra.toString()
                                    }
                                }
                            }
                            "hysteria2", "hy2" -> {
                                v2rayBean.type = "hysteria2"
                                streamSettings.getObject("hy2Settings")?.also { hy2Settings ->
                                    hy2Settings.getString("password")?.also {
                                        v2rayBean.hy2Password = it
                                    }
                                    hy2Settings.getObject("obfs")?.also { obfs ->
                                        obfs.getString("type")?.also { type ->
                                            if (type == "salamander") {
                                                return proxies
                                            }
                                        }
                                    }
                                    /*hy2Settings.getObject("congestion")?.also { congestion ->
                                        congestion.getInteger("up_mbps")?.also {
                                            v2rayBean.hy2UpMbps = it
                                        }
                                        congestion.getInteger("down_mbps")?.also {
                                            v2rayBean.hy2DownMbps = it
                                        }
                                    }*/
                                }
                            }
                            else -> return proxies
                        }
                    }
                }
                when (proto) {
                    "vmess" -> {
                        v2rayBean as VMessBean
                        (outbound.getString("tag"))?.also {
                            v2rayBean.name = it
                        }
                        outbound.getObject("settings")?.also { settings ->
                            v2rayBean.packetEncoding = when (settings.getString("packetEncoding")?.lowercase()) {
                                "xudp" -> "xudp"
                                "packet" -> "packet"
                                else -> "none"
                            }
                            (settings.getArray("vnext")?.get(0) as? JSONObject)?.also { vnext ->
                                vnext.getString("address")?.also {
                                    v2rayBean.serverAddress = it
                                }
                                vnext.getIntFromStringOrInt("port")?.also {
                                    v2rayBean.serverPort = it
                                }
                                (vnext.getArray("users")?.get(0) as? JSONObject)?.also { user ->
                                    user.getString("id")?.takeIf { it.isNotEmpty() }?.also {
                                        v2rayBean.uuid = try {
                                            UUID.fromString(it).toString(false)
                                        } catch (_: Exception) {
                                            uuid5(it)
                                        }
                                    }
                                    user.getString("security")?.lowercase()?.also {
                                        if (it !in supportedVmessMethod) return proxies
                                        v2rayBean.encryption = it
                                    }
                                    user.getInteger("alterId")?.also {
                                        v2rayBean.alterId = it
                                    }
                                    user.getString("experiments")?.also {
                                        if (it.contains("AuthenticatedLength")) {
                                            v2rayBean.experimentalAuthenticatedLength = true
                                        }
                                        if (it.contains("NoTerminationSignal")) {
                                            v2rayBean.experimentalNoTerminationSignal = true
                                        }
                                    }
                                }
                            }
                        }
                    }
                    "vless" -> {
                        v2rayBean as VLESSBean
                        (outbound.getString("tag"))?.also {
                            v2rayBean.name = it
                        }
                        outbound.getObject("settings")?.also { settings ->
                            v2rayBean.packetEncoding = when (settings.getString("packetEncoding")?.lowercase()) {
                                "xudp" -> "xudp"
                                "packet" -> "packet"
                                else -> "none"
                            }
                            (settings.getArray("vnext")?.get(0) as? JSONObject)?.also { vnext ->
                                vnext.getString("address")?.also {
                                    v2rayBean.serverAddress = it
                                }
                                vnext.getIntFromStringOrInt("port")?.also {
                                    v2rayBean.serverPort = it
                                }
                                (vnext.getArray("users")?.get(0) as? JSONObject)?.also { user ->
                                    user.getString("id")?.takeIf { it.isNotEmpty() }?.also {
                                        v2rayBean.uuid = try {
                                            UUID.fromString(it).toString(false)
                                        } catch (_: Exception) {
                                            uuid5(it)
                                        }
                                    }
                                    user.getString("flow")?.also {
                                        when (it) {
                                            in supportedVlessFlow -> {
                                                v2rayBean.flow = "xtls-rprx-vision-udp443"
                                                v2rayBean.packetEncoding = "xudp"
                                            }
                                            in legacyVlessFlow,  "", "none" -> {}
                                            else -> if (it.startsWith("xtls-rprx-")) return proxies
                                        }
                                    }
                                }
                            }
                        }
                    }
                    "shadowsocks" -> {
                        v2rayBean as ShadowsocksBean
                        outbound.getString("tag")?.also {
                            v2rayBean.name = it
                        }
                        outbound.getObject("settings")?.also { settings ->
                            (settings.getArray("servers")?.get(0) as? JSONObject)?.also { server ->
                                settings.getString("plugin")?.also { plugin ->
                                    v2rayBean.plugin = plugin
                                    settings.getString("pluginOpts").also {
                                        v2rayBean.plugin += ";$it"
                                    }
                                }
                                server.getString("address")?.also {
                                    v2rayBean.serverAddress = it
                                }
                                server.getIntFromStringOrInt("port")?.also {
                                    v2rayBean.serverPort = it
                                }
                                server.getString("method")?.lowercase()?.also {
                                    v2rayBean.method = when (it) {
                                        in supportedShadowsocksMethod -> it
                                        "aes_128_gcm", "aead_aes_128_gcm" -> "aes-128-gcm"
                                        "aes_192_gcm", "aead_aes_192_gcm" -> "aes-192-gcm"
                                        "aes_256_gcm", "aead_aes_256_gcm" -> "aes-256-gcm"
                                        "chacha20_poly1305", "aead_chacha20_poly1305", "chacha20-poly1305" -> "chacha20-ietf-poly1305"
                                        "xchacha20_poly1305", "aead_xchacha20_poly1305", "xchacha20-poly1305" -> "xchacha20-ietf-poly1305"
                                        "plain" -> "none"
                                        else -> return proxies
                                    }
                                }
                                server.getString("password")?.also {
                                    v2rayBean.password = it
                                }
                            }
                        }
                    }
                    "shadowsocks2022" -> {
                        v2rayBean as ShadowsocksBean
                        outbound.getString("tag")?.also {
                            v2rayBean.name = it
                        }
                        outbound.getObject("settings")?.also { settings ->
                            settings.getString("address")?.also {
                                v2rayBean.serverAddress = it
                            } ?: return proxies
                            settings.getIntFromStringOrInt("port")?.also {
                                v2rayBean.serverPort = it
                            } ?: return proxies
                            settings.getString("method")?.lowercase()?.also {
                                if (it !in supportedShadowsocks2022Method) return proxies // unsupported method
                                v2rayBean.method = it
                            }
                            settings.getString("psk")?.also { psk ->
                                v2rayBean.password = psk
                                (settings.getAny("ipsk") as? List<String>)?.also { ipsk ->
                                    v2rayBean.password = ipsk.joinToString(":") + ":" + psk
                                }
                            }
                            settings.getString("plugin")?.also { plugin ->
                                v2rayBean.plugin = plugin
                                settings.getString("pluginOpts")?.also {
                                    v2rayBean.plugin += ";$it"
                                }
                            }
                        }
                    }
                    "shadowsocks-2022" -> {
                        v2rayBean as ShadowsocksBean
                        outbound.getString("tag")?.also {
                            v2rayBean.name = it
                        }
                        outbound.getObject("settings")?.also { settings ->
                            settings.getString("address")?.also {
                                v2rayBean.serverAddress = it
                            }
                            settings.getIntFromStringOrInt("port")?.also {
                                v2rayBean.serverPort = it
                            }
                            settings.getString("method")?.lowercase()?.also {
                                if (it !in supportedShadowsocks2022Method) return proxies // unsupported method
                                v2rayBean.method = it
                            }
                            settings.getString("password")?.also {
                                v2rayBean.password = it
                            }
                            settings.getString("plugin")?.also { plugin ->
                                v2rayBean.plugin = plugin
                                settings.getString("pluginOpts").also {
                                    v2rayBean.plugin += ";$it"
                                }
                            }
                        }
                    }
                    "trojan" -> {
                        v2rayBean as TrojanBean
                        outbound.getString("tag")?.also {
                            v2rayBean.name = it
                        }
                        outbound.getObject("settings")?.also { settings ->
                            (settings.getArray("servers")?.get(0) as? JSONObject)?.also { server ->
                                server.getString("address")?.also {
                                    v2rayBean.serverAddress = it
                                }
                                server.getIntFromStringOrInt("port")?.also {
                                    v2rayBean.serverPort = it
                                }
                                server.getString("password")?.also {
                                    v2rayBean.password = it
                                }
                            }
                        }
                    }
                    "socks" -> {
                        v2rayBean as SOCKSBean
                        outbound.getString("tag")?.also {
                            v2rayBean.name = it
                        }
                        outbound.getObject("settings")?.also { settings ->
                            v2rayBean.protocol = when (settings.getString("version")?.lowercase()) {
                                "4" -> SOCKSBean.PROTOCOL_SOCKS4
                                "4a" -> SOCKSBean.PROTOCOL_SOCKS4A
                                "", "5" -> SOCKSBean.PROTOCOL_SOCKS5
                                else -> return proxies
                            }
                            (settings.getArray("servers")?.get(0) as? JSONObject)?.also { server ->
                                server.getString("address")?.also {
                                    v2rayBean.serverAddress = it
                                }
                                server.getIntFromStringOrInt("port")?.also {
                                    v2rayBean.serverPort = it
                                }
                                (server.getArray("users")?.get(0) as? JSONObject)?.also { user ->
                                    user.getString("username")?.also {
                                        v2rayBean.username = it
                                    }
                                    user.getString("password")?.also {
                                        v2rayBean.password = it
                                    }
                                }
                            }
                        }
                    }
                    "http" -> {
                        v2rayBean as HttpBean
                        outbound.getString("tag")?.also {
                            v2rayBean.name = it
                        }
                        outbound.getObject("settings")?.also { settings ->
                            (settings.getArray("servers")?.get(0) as? JSONObject)?.also { server ->
                                server.getString("address")?.also {
                                    v2rayBean.serverAddress = it
                                }
                                server.getIntFromStringOrInt("port")?.also {
                                    v2rayBean.serverPort = it
                                }
                                (server.getArray("users")?.get(0) as? JSONObject)?.also { user ->
                                    user.getString("username")?.also {
                                        v2rayBean.username = it
                                    }
                                    user.getString("password")?.also {
                                        v2rayBean.password = it
                                    }
                                }
                            }
                        }
                    }
                }
                proxies.add(v2rayBean)
            }
            "hysteria2" -> {
                val hysteria2Bean = Hysteria2Bean()
                outbound.getString("tag")?.also {
                    hysteria2Bean.name = it
                }
                outbound.getObject("settings")?.also { settings ->
                    (settings.getArray("servers")?.get(0) as? JSONObject)?.also { server ->
                        server.getString("address")?.also {
                            hysteria2Bean.serverAddress = it
                        }
                        server.getIntFromStringOrInt("port")?.also {
                            hysteria2Bean.serverPorts = it.toString()
                        }
                    }
                }
                outbound.getObject("streamSettings")?.also { streamSettings ->
                    streamSettings.getString("network")?.lowercase()?.also { network ->
                        when (network) {
                            "hysteria2", "hy2" -> {
                                streamSettings.getObject("hy2Settings")?.also { hy2Settings ->
                                    hy2Settings.getString("password")?.also {
                                        hysteria2Bean.auth = it
                                    }
                                    /*hy2Settings.getObject("congestion")?.also { congestion ->
                                        congestion.getInteger("up_mbps")?.also {
                                            hysteria2Bean.uploadMbps = it
                                        }
                                        congestion.getInteger("down_mbps")?.also {
                                            hysteria2Bean.downloadMbps = it
                                        }
                                    }*/
                                    hy2Settings.getObject("obfs")?.also { obfs ->
                                        obfs.getString("type")?.also { type ->
                                            if (type == "salamander") {
                                                obfs.getString("password")?.also {
                                                    hysteria2Bean.obfs = it
                                                }
                                            }
                                        }
                                    }
                                    hy2Settings.getString("hopPorts")?.takeIf { it.isValidHysteriaMultiPort() }?.also {
                                        hysteria2Bean.serverPorts = it
                                    }
                                    hy2Settings.getInteger("hopInterval")?.also {
                                        hysteria2Bean.hopInterval = it
                                    }
                                }
                            }
                            else -> return proxies
                        }
                    }
                    streamSettings.getString("security")?.lowercase()?.also { security ->
                        when (security) {
                            "tls" -> {
                                streamSettings.getObject("tlsSettings")?.also { tlsSettings ->
                                    tlsSettings.getString("serverName")?.also {
                                        hysteria2Bean.sni = it
                                    }
                                    tlsSettings.getBoolean("allowInsecure")?.also {
                                        hysteria2Bean.allowInsecure = it
                                    }
                                }
                            }
                            else -> return proxies
                        }
                    }
                }
                proxies.add(hysteria2Bean)
            }
            "wireguard" -> {
                val wireguardBean = WireGuardBean()
                outbound.getString("tag")?.also {
                    wireguardBean.name = it
                }
                outbound.getObject("settings")?.also { settings ->
                    settings.getString("secretKey")?.also {
                        // https://github.com/XTLS/Xray-core/blob/d8934cf83946e88210b6bb95d793bc06e12b6db8/infra/conf/wireguard.go#L126-L148
                        wireguardBean.privateKey = it.replace('_', '/').replace('-', '+').padEnd(44, '=')
                    }
                    // https://github.com/XTLS/Xray-core/blob/d8934cf83946e88210b6bb95d793bc06e12b6db8/infra/conf/wireguard.go#L75
                    wireguardBean.localAddress = "10.0.0.1/32\nfd59:7153:2388:b5fd:0000:0000:0000:0001/128"
                    (settings.getAny("address") as? List<String>)?.also {
                        wireguardBean.localAddress = it.joinToString("\n")
                    }
                    wireguardBean.mtu = 1420
                    settings.getInteger("mtu")?.takeIf { it > 0 }?.also {
                        wireguardBean.mtu = it
                    }
                    (settings.getAny("reserved") as? List<Int>)?.also {
                        if (it.size == 3) {
                            wireguardBean.reserved = listOf(it[0].toString(), it[1].toString(), it[2].toString()).joinToString(",")
                        }
                    }
                    (settings.getArray("peers"))?.forEach { peer ->
                        proxies.add(wireguardBean.applyDefaultValues().clone().apply {
                            (peer as? JSONObject)?.getString("endpoint")?.also {
                                serverAddress = it.substringBeforeLast(":").removePrefix("[").removeSuffix("]")
                                serverPort = it.substringAfterLast(":").toIntOrNull()
                            }
                            (peer as? JSONObject)?.getString("publicKey")?.also {
                                peerPublicKey = it.replace('_', '/').replace('-', '+').padEnd(44, '=')
                            }
                            (peer as? JSONObject)?.getString("preSharedKey")?.also {
                                peerPreSharedKey = it.replace('_', '/').replace('-', '+').padEnd(44, '=')
                            }
                            (peer as? JSONObject)?.getInt("keepAlive")?.takeIf { it > 0 }?.also {
                                keepaliveInterval = it
                            }
                        })
                    }
                }
            }
            "ssh" -> {
                outbound.getObject("streamSettings")?.also { streamSettings ->
                    streamSettings.getString("network")?.lowercase()?.also {
                        if (it in nonRawTransportName) return proxies
                    }
                    streamSettings.getString("security")?.lowercase()?.also {
                        if (it != "none") return proxies
                    }
                }
                val sshBean = SSHBean()
                outbound.getObject("settings")?.also { settings ->
                    outbound.getString("tag")?.also {
                        sshBean.name = it
                    }
                    settings.getString("address")?.also {
                        sshBean.serverAddress = it
                    }
                    settings.getIntFromStringOrInt("port")?.also {
                        sshBean.serverPort = it
                    }
                    settings.getString("user")?.also {
                        sshBean.username = it
                    }
                    settings.getString("publicKey")?.also {
                        sshBean.publicKey = it
                    }
                    settings.getString("privateKey")?.also {
                        sshBean.authType = SSHBean.AUTH_TYPE_PRIVATE_KEY
                        sshBean.privateKey = it
                        settings.getString("password")?.also { pass ->
                            sshBean.privateKeyPassphrase = pass
                        }
                    } ?: settings.getString("password")?.also {
                        sshBean.authType = SSHBean.AUTH_TYPE_PASSWORD
                        sshBean.password = it
                    }
                }
                proxies.add(sshBean)
            }
            "tuic" -> {
                val tuic5Bean = Tuic5Bean()
                outbound.getObject("settings")?.also { settings ->
                    outbound.getString("tag")?.also {
                        tuic5Bean.name = it
                    }
                    settings.getString("address")?.also {
                        tuic5Bean.serverAddress = it
                    }
                    settings.getIntFromStringOrInt("port")?.also {
                        tuic5Bean.serverPort = it
                    }
                    settings.getString("uuid")?.also {
                        tuic5Bean.uuid = it
                    }
                    settings.getString("password")?.also {
                        tuic5Bean.password = it
                    }
                    settings.getString("congestionControl")?.also {
                        tuic5Bean.congestionControl = if (it in supportedTuic5CongestionControl) it else "cubic"
                    }
                    settings.getString("udpRelayMode")?.also {
                        tuic5Bean.udpRelayMode = if (it in supportedTuic5RelayMode) it else "native"
                    }
                    settings.getBoolean("zeroRTTHandshake")?.also {
                        tuic5Bean.zeroRTTHandshake = it
                    }
                    settings.getObject("tlsSettings")?.also { tlsSettings ->
                        tlsSettings.getString("serverName")?.also {
                            tuic5Bean.sni = it
                        }
                        tlsSettings.getBoolean("allowInsecure")?.also {
                            tuic5Bean.allowInsecure = it
                        }
                        (tlsSettings.getAny("alpn") as? List<String>)?.also {
                            tuic5Bean.alpn = it.joinToString("\n")
                        } ?: tlsSettings.getString("alpn")?.also {
                            tuic5Bean.alpn = it.split(",").joinToString("\n")
                        }
                    }
                    settings.getBoolean("disableSNI")?.also {
                        tuic5Bean.disableSNI = it
                    }
                }
                proxies.add(tuic5Bean)
            }
            "http3" -> {
                val http3Bean = Http3Bean()
                outbound.getObject("settings")?.also { settings ->
                    outbound.getString("tag")?.also {
                        http3Bean.name = it
                    }
                    settings.getString("address")?.also {
                        http3Bean.serverAddress = it
                    }
                    settings.getIntFromStringOrInt("port")?.also {
                        http3Bean.serverPort = it
                    }
                    settings.getString("username")?.also {
                        http3Bean.username = it
                    }
                    settings.getString("password")?.also {
                        http3Bean.password = it
                    }
                    settings.getObject("tlsSettings")?.also { tlsSettings ->
                        tlsSettings.getString("serverName")?.also {
                            http3Bean.sni = it
                        }
                        tlsSettings.getBoolean("allowInsecure")?.also {
                            http3Bean.allowInsecure = it
                        }
                        (tlsSettings.getObject("pinnedPeerCertificateChainSha256") as? List<String>)?.also {
                            http3Bean.pinnedPeerCertificateChainSha256 = it.joinToString("\n")
                            tlsSettings.getBoolean("allowInsecureIfPinnedPeerCertificate")?.also { allowInsecure ->
                                http3Bean.allowInsecure = allowInsecure
                            }
                        }
                    }
                }
                proxies.add(http3Bean)
            }
            "anytls" -> {
                outbound.getObject("streamSettings")?.also { streamSettings ->
                    streamSettings.getString("network")?.lowercase()?.also {
                        if (it in nonRawTransportName) return proxies
                    }
                }
                val anytlsBean = AnyTLSBean()
                outbound.getObject("settings")?.also { settings ->
                    outbound.getString("tag")?.also {
                        anytlsBean.name = it
                    }
                    settings.getString("address")?.also {
                        anytlsBean.serverAddress = it
                    }
                    settings.getIntFromStringOrInt("port")?.also {
                        anytlsBean.serverPort = it
                    }
                    settings.getString("password")?.also {
                        anytlsBean.password = it
                    }
                }
                outbound.getObject("streamSettings")?.also { streamSettings ->
                    when (val security = streamSettings.getString("security")?.lowercase()) {
                        "tls", "utls" -> {
                            anytlsBean.security = "tls"
                            var tlsConfig = streamSettings.getObject("tlsSettings")
                            if (security == "utls") {
                                streamSettings.getObject("utlsSettings")?.also {
                                    tlsConfig = it.getObject("tlsConfig")
                                }
                            }
                            tlsConfig?.also { tlsSettings ->
                                tlsSettings.getString("serverName")?.also {
                                    anytlsBean.sni = it
                                }
                                (tlsSettings.getAny("alpn") as? List<String>)?.also {
                                    anytlsBean.alpn = it.joinToString("\n")
                                } ?: tlsSettings.getString("alpn")?.also {
                                    anytlsBean.alpn = it.split(",").joinToString("\n")
                                }
                                tlsSettings.getBoolean("allowInsecure")?.also {
                                    anytlsBean.allowInsecure = it
                                }
                                (tlsSettings.getObject("pinnedPeerCertificateChainSha256") as? List<String>)?.also {
                                    anytlsBean.pinnedPeerCertificateChainSha256 = it.joinToString("\n")
                                    tlsSettings.getBoolean("allowInsecureIfPinnedPeerCertificate")?.also { allowInsecure ->
                                        anytlsBean.allowInsecure = allowInsecure
                                    }
                                }
                                // tlsSettings.getString("imitate")
                                // tlsSettings.getString("fingerprint")
                            }
                        }
                        "reality" -> {
                            anytlsBean.security = "reality"
                            streamSettings.getObject("realitySettings")?.also { realitySettings ->
                                realitySettings.getString("serverName")?.also {
                                    anytlsBean.sni = it
                                }
                                realitySettings.getString("publicKey")?.also {
                                    anytlsBean.realityPublicKey = it
                                }
                                realitySettings.getString("shortId")?.also {
                                    anytlsBean.realityShortId = it
                                }
                                // realitySettings.getString("fingerprint")
                            }
                        }
                        else -> anytlsBean.security = "none"
                    }
                }
                proxies.add(anytlsBean)
            }
        }
        return proxies
    }

    @Suppress("UNCHECKED_CAST")
    private fun parseSingBoxOutbound(outbound: JSONObject): List<AbstractBean> {
        val proxies = ArrayList<AbstractBean>()
        when (val type = outbound["type"]) {
            "shadowsocks", "trojan", "vmess", "vless", "socks", "http" -> {
                val v2rayBean = when (type) {
                    "shadowsocks" -> ShadowsocksBean()
                    "trojan" -> TrojanBean()
                    "vmess" -> VMessBean()
                    "vless" -> VLESSBean()
                    "socks" -> SOCKSBean()
                    "http" -> HttpBean()
                    else -> return proxies
                }.apply {
                    outbound["tag"]?.toString()?.also {
                        name = it
                    }
                    outbound.getString("server")?.also {
                        serverAddress = it
                    } ?: return proxies
                    outbound.getInteger("server_port")?.also {
                        serverPort = it
                    } ?: return proxies
                }
                when (type) {
                    "trojan", "vmess", "vless" -> {
                        outbound.getObject("transport")?.takeIf { !it.isEmpty() }?.also { transport ->
                            when (transport["type"]) {
                                "ws" -> {
                                    v2rayBean.type = "ws"
                                    transport.getString("path")?.also {
                                        v2rayBean.path = it
                                    }
                                    transport.getObject("headers")?.also { headers ->
                                        (headers.getAny("host") as? (List<String>))?.get(0)?.also {
                                            v2rayBean.host = it
                                        } ?: headers.getString("host")?.also {
                                            v2rayBean.host = it
                                        }
                                    }
                                    transport.getInteger("max_early_data")?.also {
                                        v2rayBean.maxEarlyData = it
                                    }
                                    transport.getString("early_data_header_name")?.also {
                                        v2rayBean.earlyDataHeaderName = it
                                    }
                                }
                                "http" -> {
                                    v2rayBean.type = "tcp"
                                    v2rayBean.headerType = "http"
                                    // Difference from v2ray-core
                                    // TLS is not enforced. If TLS is not configured, plain HTTP 1.1 is used.
                                    outbound.getObject("tls")?.also {
                                        if (it.getBoolean("enabled") == true) {
                                            v2rayBean.type = "http"
                                            v2rayBean.headerType = null
                                        }
                                    }
                                    transport.getString("path")?.also {
                                        v2rayBean.path = it
                                    }
                                    (transport.getAny("host") as? (List<String>))?.also {
                                        v2rayBean.host = it.joinToString("\n")
                                    } ?: transport.getString("host")?.also {
                                        v2rayBean.host = it
                                    }

                                }
                                "quic" -> {
                                    v2rayBean.type = "quic"
                                }
                                "grpc" -> {
                                    v2rayBean.type = "grpc"
                                    transport.getString("service_name")?.also {
                                        v2rayBean.grpcServiceName = it
                                    }
                                }
                                "httpupgrade" -> {
                                    v2rayBean.type = "httpupgrade"
                                    transport.getString("host")?.also {
                                        v2rayBean.host = it
                                    }
                                    transport.getString("path")?.also {
                                        v2rayBean.path = it
                                    }
                                }
                                else -> return proxies
                            }
                        }
                    }
                }
                when (type) {
                    "trojan", "vmess", "vless", "http" -> {
                        outbound.getObject("tls")?.also { tls ->
                            (tls.getBoolean("enabled"))?.also { enabled ->
                                if (enabled) {
                                    v2rayBean.security = "tls"
                                    tls.getString("server_name")?.also {
                                        v2rayBean.sni = it
                                    }
                                    tls.getBoolean("insecure")?.also {
                                        v2rayBean.allowInsecure = it
                                    }
                                    (tls.getAny("alpn") as? (List<String>))?.also {
                                        v2rayBean.alpn = it.joinToString("\n")
                                    } ?: tls.getString("alpn")?.also {
                                        v2rayBean.alpn = it
                                    }
                                    tls.getObject("reality")?.also { reality ->
                                        reality.getBoolean("enabled")?.also { enabled ->
                                            if (enabled) {
                                                v2rayBean.security = "reality"
                                                reality.getString("public_key")?.also {
                                                    v2rayBean.realityPublicKey = it
                                                }
                                                reality.getString("short_id")?.also {
                                                    v2rayBean.realityShortId = it
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                when (type) {
                    "socks" -> {
                        v2rayBean as SOCKSBean
                        outbound.getString("version")?.also {
                            v2rayBean.protocol = when (it) {
                                "4" -> SOCKSBean.PROTOCOL_SOCKS4
                                "4a" -> SOCKSBean.PROTOCOL_SOCKS4A
                                "", "5" -> SOCKSBean.PROTOCOL_SOCKS5
                                else -> return proxies
                            }
                        }
                        outbound.getString("username")?.also {
                            v2rayBean.username = it
                        }
                        outbound.getString("password")?.also {
                            v2rayBean.password = it
                        }
                    }
                    "http" -> {
                        v2rayBean as HttpBean
                        outbound.getString("path")?.also {
                            if (it != "" && it != "/") return proxies
                        }
                        outbound.getString("username")?.also {
                            v2rayBean.username = it
                        }
                        outbound.getString("password")?.also {
                            v2rayBean.password = it
                        }
                    }
                    "shadowsocks" -> {
                        v2rayBean as ShadowsocksBean
                        outbound.getString("method")?.also {
                            if (it !in supportedShadowsocksMethod) return proxies
                            v2rayBean.method = it
                        }
                        outbound.getString("password")?.also {
                            v2rayBean.password = it
                        }
                        outbound.getString("plugin")?.also { p ->
                            if (p != "obfs-local" && p != "v2ray-plugin") return proxies
                            v2rayBean.plugin = p
                            outbound.getString("plugin_opts")?.also {
                                v2rayBean.plugin += ";$it"
                            }
                        }
                    }
                    "trojan" -> {
                        v2rayBean as TrojanBean
                        outbound.getString("password")?.also {
                            v2rayBean.password = it
                        }
                    }
                    "vmess" -> {
                        v2rayBean as VMessBean
                        outbound.getString("uuid")?.takeIf { it.isNotEmpty() }?.also {
                            v2rayBean.uuid = try {
                                UUID.fromString(it).toString(false)
                            } catch (_: Exception) {
                                uuid5(it)
                            }
                        }
                        outbound.getString("security")?.also {
                            if (it !in supportedVmessMethod) return proxies
                            v2rayBean.encryption = it
                        }
                        outbound.getInteger("alter_id")?.also {
                            v2rayBean.alterId = it
                        }
                        outbound.getBoolean("global_padding")?.also {
                            v2rayBean.experimentalAuthenticatedLength = it
                        }
                        v2rayBean.packetEncoding = when (outbound.getString("packet_encoding")) {
                            "packetaddr" -> "packet"
                            "xudp" -> "xudp"
                            else -> "none"
                        }
                    }
                    "vless" -> {
                        v2rayBean as VLESSBean
                        outbound.getString("uuid")?.takeIf { it.isNotEmpty() }?.also {
                            v2rayBean.uuid = try {
                                UUID.fromString(it).toString(false)
                            } catch (_: Exception) {
                                uuid5(it)
                            }
                        }
                        v2rayBean.packetEncoding = when (outbound.getString("packet_encoding")) {
                            "packetaddr" -> "packet"
                            "xudp", null -> "xudp"
                            else -> "none"
                        }
                        outbound.getString("flow")?.also {
                            when (it) {
                                "" -> {}
                                "xtls-rprx-vision" -> {
                                    v2rayBean.flow = "xtls-rprx-vision-udp443"
                                    v2rayBean.packetEncoding = "xudp"
                                }
                                else -> return proxies
                            }
                        }
                    }
                }
                proxies.add(v2rayBean)
            }
            "hysteria2" -> {
                val hysteria2Bean = Hysteria2Bean().apply {
                    outbound["tag"]?.toString()?.also {
                        name = it
                    }
                    outbound.getString("server")?.also {
                        serverAddress = it
                    } ?: return proxies
                    outbound.getInteger("server_port")?.also {
                        serverPorts = it.toString()
                    } ?: (outbound.getAny("server_ports") as? List<String>)?.also {
                        serverPorts = it.joinToString(",").replace(":", "-")
                    } ?: (outbound.getAny("server_ports") as? String)?.also {
                        serverPorts = it.replace(":", "-")
                    } ?: return proxies
                    if (!serverPorts.isValidHysteriaPort()) {
                        return proxies
                    }
                    outbound.getString("hop_interval")?.also {
                        try {
                            val duration = Duration.parse(it)
                            hopInterval = duration.toInt(DurationUnit.SECONDS)
                        } catch (_: Exception) {}
                    }
                    outbound.getString("password")?.also {
                        auth = it
                    }
                    outbound.getObject("tls")?.also { tls ->
                        if (tls.getBoolean("enabled") != true) {
                            return proxies
                        }
                        if (tls.getObject("reality")?.getBoolean("enabled") == true) {
                            return proxies
                        }
                        tls.getString("server_name")?.also {
                            sni = it
                        }
                        tls.getBoolean("insecure")?.also {
                            allowInsecure = it
                        }
                    } ?: return proxies
                    outbound.getObject("obfs")?.also { obfuscation ->
                        if (obfuscation.getString("type") != "salamander") {
                            return proxies
                        }
                        obfuscation.getString("password")?.also {
                            obfs = it
                        }
                    }
                    /*outbound.getInt("up_mbps")?.also {
                        uploadMbps = it
                    }
                    outbound.getInt("down_mbps")?.also {
                        downloadMbps = it
                    }*/
                }
                proxies.add(hysteria2Bean)
            }
            "hysteria" -> {
                val hysteriaBean = HysteriaBean().apply {
                    outbound["tag"]?.toString()?.also {
                        name = it
                    }
                    outbound.getString("server")?.also {
                        serverAddress = it
                    } ?: return proxies
                    outbound.getInteger("server_port")?.also {
                        serverPorts = it.toString()
                    } ?: (outbound.getAny("server_ports") as? List<String>)?.also {
                        serverPorts = it.joinToString(",").replace(":", "-")
                    } ?: (outbound.getAny("server_ports") as? String)?.also {
                        serverPorts = it.replace(":", "-")
                    } ?: return proxies
                    if (!serverPorts.isValidHysteriaPort()) {
                        return proxies
                    }
                    outbound.getString("hop_interval")?.also {
                        try {
                            val duration = Duration.parse(it)
                            hopInterval = duration.toInt(DurationUnit.SECONDS)
                        } catch (_: Exception) {}
                    }
                    if (outbound.getString("auth")?.isNotEmpty() == true) {
                        authPayloadType = HysteriaBean.TYPE_BASE64
                        outbound.getString("auth")?.also {
                            authPayload = it
                        }
                    }
                    if (outbound.getString("auth_str")?.isNotEmpty() == true) {
                        authPayloadType = HysteriaBean.TYPE_STRING
                        outbound.getString("auth_str")?.also {
                            authPayload = it
                        }
                    }
                    outbound.getString("obfs")?.also {
                        obfuscation = it
                    }
                    outbound.getObject("tls")?.also { tls ->
                        if (tls.getBoolean("enabled") != true) {
                            return proxies
                        }
                        if (tls.getObject("reality")?.getBoolean("enabled") == true) {
                            return proxies
                        }
                        tls.getString("server_name")?.also {
                            sni = it
                        }
                        (tls.getAny("alpn") as? (List<String>))?.also {
                            alpn = it[0]
                        } ?: tls.getString("alpn")?.also {
                            alpn = it
                        }
                        tls.getBoolean("insecure")?.also {
                            allowInsecure = it
                        }
                    } ?: return proxies
                    outbound.getInt("up_mbps")?.also {
                        uploadMbps = it
                    } ?: outbound.getString("up")?.toMegaBits()?.also {
                        uploadMbps = it
                    }
                    outbound.getInt("down_mbps")?.also {
                        downloadMbps = it
                    } ?: outbound.getString("down")?.toMegaBits()?.also {
                        downloadMbps = it
                    }
                }
                proxies.add(hysteriaBean)
            }
            "tuic" -> {
                val tuic5Bean = Tuic5Bean().apply {
                    outbound["tag"]?.toString()?.also {
                        name = it
                    }
                    outbound.getString("server")?.also {
                        serverAddress = it
                    } ?: return proxies
                    outbound.getInteger("server_port")?.also {
                        serverPort = it
                    } ?: return proxies
                    outbound.getString("uuid")?.also {
                        uuid = it
                    }
                    outbound.getString("password")?.also {
                        password = it
                    }
                    outbound.getString("congestion_control")?.also {
                        congestionControl = if (it in supportedTuic5CongestionControl) it else "cubic"
                    }
                    outbound.getString("udp_relay_mode")?.also {
                        udpRelayMode = if (it in supportedTuic5RelayMode) it else "native"
                    }
                    outbound.getBoolean("zero_rtt_handshake")?.also {
                        zeroRTTHandshake = it
                    }
                    outbound.getObject("tls")?.also { tls ->
                        if (tls.getBoolean("enabled") != true) {
                            return proxies
                        }
                        if (tls.getObject("reality")?.getBoolean("enabled") == true) {
                            return proxies
                        }
                        tls.getString("server_name")?.also {
                            sni = it
                        }
                        (tls.getAny("alpn") as? (List<String>))?.also {
                            alpn = it.joinToString("\n")
                        } ?: tls.getString("alpn")?.also {
                            alpn = it
                        }
                        tls.getBoolean("insecure")?.also {
                            allowInsecure = it
                        }
                        tls.getBoolean("disable_sni")?.also {
                            disableSNI = it
                        }
                    } ?: return proxies
                }
                proxies.add(tuic5Bean)
            }
            "ssh" -> {
                val sshBean = SSHBean().apply {
                    outbound["tag"]?.toString()?.also {
                        name = it
                    }
                    outbound.getString("server")?.also {
                        serverAddress = it
                    } ?: return proxies
                    outbound.getInteger("server_port")?.also {
                        serverPort = it
                    } ?: return proxies
                    outbound.getString("user")?.also {
                        username = it
                    }
                    if (outbound.getString("password")?.isNotEmpty() == true) {
                        authType = SSHBean.AUTH_TYPE_PASSWORD
                        outbound.getString("password")?.also {
                            password = it
                        }
                    }
                    if (outbound.getString("private_key")?.isNotEmpty() == true) {
                        authType = SSHBean.AUTH_TYPE_PRIVATE_KEY
                        outbound.getString("private_key")?.also {
                            privateKey = it
                        }
                        outbound.getString("private_key_passphrase")?.also {
                            privateKeyPassphrase = it
                        }
                    }
                    (outbound.getAny("host_key") as? List<String>)?.also {
                        publicKey = it.joinToString("\n")
                    }
                }
                proxies.add(sshBean)
            }
            "ssr" -> {
                // removed in v1.6.0
                val ssrBean = ShadowsocksRBean().apply {
                    outbound["tag"]?.toString()?.also {
                        name = it
                    }
                    outbound.getString("server")?.also {
                        serverAddress = it
                    } ?: return proxies
                    outbound.getInteger("server_port")?.also {
                        serverPort = it
                    } ?: return proxies
                    outbound.getString("method")?.also {
                        if (it !in supportedShadowsocksRMethod) return proxies
                        method = it
                    }
                    outbound.getString("password")?.also {
                        password = it
                    }
                    outbound.getString("obfs")?.also {
                        obfs = when (it) {
                            "tls1.2_ticket_fastauth" -> "tls1.2_ticket_auth"
                            in supportedShadowsocksRObfs -> it
                            else -> return proxies
                        }
                    }
                    outbound.getString("obfs_param")?.also {
                        obfsParam = it
                    }
                    outbound.getString("protocol")?.also {
                        if (it !in supportedShadowsocksRProtocol) return proxies
                        protocol = it
                    }
                    outbound.getString("protocol_param")?.also {
                        protocolParam = it
                    }
                }
                proxies.add(ssrBean)
            }
            "wireguard" -> {
                if (outbound.contains("address")) {
                    // wireguard endpoint format introduced in 1.11.0-alpha.19
                    return proxies
                }
                val wireGuardBean = WireGuardBean().apply {
                    outbound["tag"]?.toString()?.also {
                        name = it
                    }
                    outbound.getString("private_key")?.also {
                        privateKey = it
                    }
                    outbound.getString("peer_public_key")?.also {
                        peerPublicKey = it
                    }
                    outbound.getString("pre_shared_key")?.also {
                        peerPreSharedKey = it
                    }
                    mtu = 1408
                    outbound.getInteger("mtu")?.takeIf { it > 0 }?.also {
                        mtu = it
                    }
                    (outbound.getAny("local_address") as? (List<String>))?.also {
                        localAddress = it.joinToString("\n")
                    } ?: outbound.getString("local_address")?.also {
                        localAddress = it
                    } ?: return proxies
                    (outbound.getAny("reserved") as? (List<Int>))?.also {
                        if (it.size == 3) {
                            reserved = listOf(it[0].toString(), it[1].toString(), it[2].toString()).joinToString(",")
                        }
                    } ?: Base64.decode(outbound.getString("reserved"))?.also {
                        if (it.size == 3) {
                            reserved = listOf(it[0].toUByte().toInt().toString(), it[1].toUByte().toInt().toString(), it[2].toUByte().toInt().toString()).joinToString(",")
                        }
                    }
                }
                if (outbound.contains("server")) {
                    outbound.getString("server")?.also {
                        wireGuardBean.serverAddress = it
                    } ?: return proxies
                    outbound.getInteger("server_port")?.also {
                        wireGuardBean.serverPort = it
                    } ?: return proxies
                    proxies.add(wireGuardBean)
                }
                outbound.getArray("peers")?.forEach { json ->
                    val peer = json as? JSONObject
                    proxies.add(wireGuardBean.applyDefaultValues().clone().apply {
                        peer?.getString("server")?.also {
                            serverAddress = it
                        }
                        peer?.getInteger("server_port")?.also {
                            serverPort = it
                        }
                        peer?.getString("public_key")?.also {
                            peerPublicKey = it
                        }
                        peer?.getString("pre_shared_key")?.also {
                            peerPreSharedKey = it
                        }
                        peer?.getString("persistent_keepalive_interval")?.toIntOrNull()?.takeIf { it > 0 }?.also {
                            keepaliveInterval = it
                        }
                        (peer?.getAny("reserved") as? (List<Int>))?.also {
                            if (it.size == 3) {
                                reserved = listOf(it[0].toString(), it[1].toString(), it[2].toString()).joinToString(",")
                            }
                        } ?: Base64.decode(peer?.getString("reserved"))?.also {
                            if (it.size == 3) {
                                reserved = listOf(it[0].toUByte().toInt().toString(), it[1].toUByte().toInt().toString(), it[2].toUByte().toInt().toString()).joinToString(",")
                            }
                        }
                    })
                }
            }
            "anytls" -> {
                val anytlsBean = AnyTLSBean().apply {
                    outbound["tag"]?.toString()?.also {
                        name = it
                    }
                    outbound.getString("server")?.also {
                        serverAddress = it
                    } ?: return proxies
                    outbound.getInteger("server_port")?.also {
                        serverPort = it
                    } ?: return proxies
                    outbound.getObject("tls")?.also { tls ->
                        (tls.getBoolean("enabled"))?.also { enabled ->
                            if (enabled) {
                                security = "tls"
                                tls.getString("server_name")?.also {
                                    sni = it
                                }
                                tls.getBoolean("insecure")?.also {
                                    allowInsecure = it
                                }
                                (tls.getAny("alpn") as? (List<String>))?.also {
                                    alpn = it.joinToString("\n")
                                } ?: tls.getString("alpn")?.also {
                                    alpn = it
                                }
                                tls.getObject("reality")?.also { reality ->
                                    reality.getBoolean("enabled")?.also { enabled ->
                                        if (enabled) {
                                            security = "reality"
                                            reality.getString("public_key")?.also {
                                                realityPublicKey = it
                                            }
                                            reality.getString("short_id")?.also {
                                                realityShortId = it
                                            }
                                        }
                                    }
                                }
                            } else {
                                security = "none"
                            }
                        }
                    }
                }
                proxies.add(anytlsBean)
            }
        }
        return proxies
    }

    @Suppress("UNCHECKED_CAST")
    private fun parseSingBoxEndpoint(endpoint: JSONObject): List<AbstractBean> {
        val proxies = ArrayList<AbstractBean>()
        when (endpoint["type"]) {
            "wireguard" -> {
                if (endpoint.contains("local_address")) {
                    // legacy wireguard outbound format
                    return proxies
                }
                val wireGuardBean = WireGuardBean().apply {
                    endpoint["tag"]?.toString()?.also {
                        name = it
                    }
                    endpoint.getString("private_key")?.also {
                        privateKey = it
                    }
                    mtu = 1408
                    endpoint.getInteger("mtu")?.takeIf { it > 0 }?.also {
                        mtu = it
                    }
                    (endpoint.getAny("address") as? (List<String>))?.also {
                        localAddress = it.joinToString("\n")
                    } ?: endpoint.getString("address")?.also {
                        localAddress = it
                    } ?: return proxies
                }
                endpoint.getArray("peers")?.forEach { json ->
                    val peer = json as? JSONObject
                    proxies.add(wireGuardBean.applyDefaultValues().clone().apply {
                        peer?.getString("address")?.also {
                            serverAddress = it
                        }
                        peer?.getInteger("port")?.also {
                            serverPort = it
                        }
                        peer?.getString("public_key")?.also {
                            peerPublicKey = it
                        }
                        peer?.getString("pre_shared_key")?.also {
                            peerPreSharedKey = it
                        }
                        peer?.getString("persistent_keepalive_interval")?.toIntOrNull()?.takeIf { it > 0 }?.also {
                            keepaliveInterval = it
                        }
                        (peer?.getAny("reserved") as? (List<Int>))?.also {
                            if (it.size == 3) {
                                reserved = listOf(it[0].toString(), it[1].toString(), it[2].toString()).joinToString(",")
                            }
                        } ?: Base64.decode(peer?.getString("reserved"))?.also {
                            if (it.size == 3) {
                                reserved = listOf(it[0].toUByte().toInt().toString(), it[1].toUByte().toInt().toString(), it[2].toUByte().toInt().toString()).joinToString(",")
                            }
                        }
                    })
                }
            }
        }
        return proxies
    }

    @Suppress("UNCHECKED_CAST")
    private fun parseV2ray5Outbound(outbound: JSONObject): List<AbstractBean> {
        val proxies = ArrayList<AbstractBean>()
        when (val type = outbound.getString("protocol")) {
            "shadowsocks", "trojan", "vmess", "vless", "socks", "http", "shadowsocks2022" -> {
                val v2rayBean = when (type) {
                    "shadowsocks", "shadowsocks2022" -> ShadowsocksBean()
                    "trojan" -> TrojanBean()
                    "vmess" -> VMessBean()
                    "vless" -> VLESSBean()
                    "socks" -> SOCKSBean()
                    "http" -> HttpBean()
                    else -> return proxies
                }.apply {
                    outbound.getString("tag")?.also {
                        name = it
                    }
                }
                outbound.getObject("streamSettings")?.also { streamSettings ->
                    if (streamSettings.contains("network") || streamSettings.contains("tlsSettings")
                        || streamSettings.contains("tcpSettings") || streamSettings.contains("kcpSettings")
                        || streamSettings.contains("wsSettings") || streamSettings.contains("httpSettings")
                        || streamSettings.contains("grpcSettings") || streamSettings.contains("gunSettings")
                        || streamSettings.contains("quicSettings") || streamSettings.contains("hy2Settings")) { // jsonv4
                        return proxies
                    }
                    streamSettings.getString("security")?.also { security ->
                        when (security) {
                            "none" -> {}
                            "tls", "utls" -> {
                                v2rayBean.security = "tls"
                                val securitySettings = streamSettings.getObject("securitySettings")
                                val tls = if (security == "tls") {
                                    securitySettings
                                } else {
                                    securitySettings?.get("tlsConfig") as? JSONObject
                                        ?: securitySettings?.get("tls_config") as? JSONObject
                                }
                                tls?.also { tlsConfig ->
                                    (tlsConfig["serverName"]?.toString() ?: tlsConfig["server_name"]?.toString())?.also {
                                        v2rayBean.sni = it
                                    }
                                    (tlsConfig["pinnedPeerCertificateChainSha256"] as? List<String>
                                        ?: tlsConfig["pinned_peer_certificate_chain_sha256"] as? List<String>)?.also {
                                        v2rayBean.pinnedPeerCertificateChainSha256 = it.joinToString("\n")
                                        (tlsConfig["allowInsecureIfPinnedPeerCertificate"] as? Boolean
                                            ?: tlsConfig["allow_insecure_if_pinned_peer_certificate"] as? Boolean)?.also { allowInsecure ->
                                            v2rayBean.allowInsecure = allowInsecure
                                        }
                                    }
                                    (tlsConfig["nextProtocol"] as? List<String>)?.also {
                                        v2rayBean.alpn = it.joinToString("\n")
                                    } ?: (tlsConfig["next_protocol"] as? List<String>)?.also {
                                        v2rayBean.alpn = it.joinToString("\n")
                                    }
                                    // tlsConfig["imitate"]
                                }
                            }
                            else -> return proxies
                        }
                    }
                    streamSettings.getString("transport")?.also { transport ->
                        when (transport) {
                            "tcp" -> {
                                v2rayBean.type = "tcp"
                                streamSettings.getObject("transportSettings")?.also { transportSettings ->
                                    (transportSettings["headerSettings"] as? JSONObject)
                                        ?: (transportSettings["header_settings"] as? JSONObject)?.also { headerSettings ->
                                            when (headerSettings["@type"] as? String) {
                                                "v2ray.core.transport.internet.headers.http.Config" -> {
                                                    v2rayBean.headerType = "http"
                                                    (headerSettings["request"] as? JSONObject)?.also { request ->
                                                        (request["uri"] as? List<String>)?.also {
                                                            v2rayBean.path = it.joinToString("\n")
                                                        }
                                                        (request.getAny("header") as? Map<String, List<String>>)?.forEach { (key, value) ->
                                                            when (key.lowercase()) {
                                                                "host" -> {
                                                                    v2rayBean.host = value.joinToString("\n")
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                }
                            }
                            "kcp" -> {
                                v2rayBean.type = "kcp"
                                streamSettings.getObject("transportSettings")?.also { transportSettings ->
                                    transportSettings["seed"]?.toString()?.also {
                                        v2rayBean.mKcpSeed = it
                                    }
                                    when ((transportSettings["headerConfig"] as? JSONObject)?.get("@type") as? String
                                        ?: (transportSettings["header_config"] as? JSONObject)?.get("@type") as? String) {
                                        null, "types.v2fly.org/v2ray.core.transport.internet.headers.noop.Config",
                                        "types.v2fly.org/v2ray.core.transport.internet.headers.noop.ConnectionConfig" -> v2rayBean.headerType = "none"
                                        "types.v2fly.org/v2ray.core.transport.internet.headers.srtp.Config" -> v2rayBean.headerType = "srtp"
                                        "types.v2fly.org/v2ray.core.transport.internet.headers.utp.Config" -> v2rayBean.headerType = "utp"
                                        "types.v2fly.org/v2ray.core.transport.internet.headers.wechat.VideoConfig" -> v2rayBean.headerType = "wechat-video"
                                        "types.v2fly.org/v2ray.core.transport.internet.headers.tls.PacketConfig" -> v2rayBean.headerType = "dtls"
                                        "types.v2fly.org/v2ray.core.transport.internet.headers.wireguard.WireguardConfig" -> v2rayBean.headerType = "wireguard"
                                        else -> return proxies
                                    }
                                }
                            }
                            "ws" -> {
                                v2rayBean.type = "ws"
                                streamSettings.getObject("transportSettings")?.also { transportSettings ->
                                    transportSettings["path"]?.toString()?.also {
                                        v2rayBean.path = it
                                    }
                                    (transportSettings["maxEarlyData"]?.toString()?.toInt()
                                        ?: transportSettings["max_early_data"]?.toString()?.toInt())?.also {
                                        v2rayBean.maxEarlyData = it
                                    }
                                    (transportSettings["earlyDataHeaderName"]?.toString()
                                        ?: transportSettings["early_data_header_name"]?.toString())?.also {
                                        v2rayBean.earlyDataHeaderName = it
                                    }
                                    (transportSettings["header"] as? Map<String, String>)?.forEach { (key, value) ->
                                        when (key.lowercase()) {
                                            "host" -> {
                                                v2rayBean.host = value
                                            }
                                        }
                                    }
                                }
                            }
                            "h2" -> {
                                v2rayBean.type = "http"
                                streamSettings.getObject("transportSettings")?.also { transportSettings ->
                                    transportSettings["path"]?.toString()?.also {
                                        v2rayBean.path = it
                                    }
                                    (transportSettings["host"] as? List<String>)?.also {
                                        v2rayBean.host = it.joinToString("\n")
                                    }
                                }
                            }
                            "quic" -> {
                                v2rayBean.type = "quic"
                                streamSettings.getObject("transportSettings")?.also { transportSettings ->
                                    transportSettings["security"]?.toString()?.lowercase()?.also {
                                        if (it !in supportedQuicSecurity) return proxies
                                        v2rayBean.quicSecurity = it
                                    }
                                    transportSettings["key"]?.toString()?.also {
                                        v2rayBean.quicKey = it
                                    }
                                    when ((transportSettings["header"] as? JSONObject)?.get("@type") as? String) {
                                        null, "types.v2fly.org/v2ray.core.transport.internet.headers.noop.Config",
                                        "types.v2fly.org/v2ray.core.transport.internet.headers.noop.ConnectionConfig" -> v2rayBean.headerType = "none"
                                        "types.v2fly.org/v2ray.core.transport.internet.headers.srtp.Config" -> v2rayBean.headerType = "srtp"
                                        "types.v2fly.org/v2ray.core.transport.internet.headers.utp.Config" -> v2rayBean.headerType = "utp"
                                        "types.v2fly.org/v2ray.core.transport.internet.headers.wechat.VideoConfig" -> v2rayBean.headerType = "wechat-video"
                                        "types.v2fly.org/v2ray.core.transport.internet.headers.tls.PacketConfig" -> v2rayBean.headerType = "dtls"
                                        "types.v2fly.org/v2ray.core.transport.internet.headers.wireguard.WireguardConfig" -> v2rayBean.headerType = "wireguard"
                                        else -> return proxies
                                    }
                                }
                            }
                            "grpc" -> {
                                v2rayBean.type = "grpc"
                                streamSettings.getObject("transportSettings")?.also { transportSettings ->
                                    (transportSettings["serviceName"]?.toString()
                                        ?: transportSettings["service_name"]?.toString())?.also {
                                        v2rayBean.grpcServiceName = it
                                    }
                                }
                            }
                            "httpupgrade" -> {
                                v2rayBean.type = "httpupgrade"
                                streamSettings.getObject("transportSettings")?.also { transportSettings ->
                                    transportSettings["path"]?.toString()?.also {
                                        v2rayBean.path = it
                                    }
                                    transportSettings["host"]?.toString()?.also {
                                        v2rayBean.host = it
                                    }
                                    (transportSettings["maxEarlyData"]?.toString()?.toInt()
                                        ?: transportSettings["max_early_data"]?.toString()?.toInt())?.also {
                                        v2rayBean.maxEarlyData = it
                                    }
                                    (transportSettings["earlyDataHeaderName"]?.toString()
                                        ?: transportSettings["early_data_header_name"]?.toString())?.also {
                                        v2rayBean.earlyDataHeaderName = it
                                    }
                                }
                            }
                            "meek" -> {
                                v2rayBean.type = "meek"
                                streamSettings.getObject("transportSettings")?.also { transportSettings ->
                                    transportSettings["url"]?.toString()?.also {
                                        v2rayBean.meekUrl = it
                                    }
                                }
                            }
                            "mekya" -> {
                                v2rayBean.type = "mekya"
                                streamSettings.getObject("transportSettings")?.also { transportSettings ->
                                    transportSettings["url"]?.toString()?.also {
                                        v2rayBean.mekyaUrl = it
                                    }
                                    (transportSettings["kcp"] as? JSONObject)?.also { kcp ->
                                        kcp["seed"]?.toString()?.also {
                                            v2rayBean.mekyaKcpSeed = it
                                        }
                                        when ((kcp["headerConfig"] as? JSONObject)?.get("@type") as? String
                                            ?: (kcp["header_config"] as? JSONObject)?.get("@type") as? String) {
                                            null, "types.v2fly.org/v2ray.core.transport.internet.headers.noop.Config",
                                            "types.v2fly.org/v2ray.core.transport.internet.headers.noop.ConnectionConfig" -> v2rayBean.headerType = "none"
                                            "types.v2fly.org/v2ray.core.transport.internet.headers.srtp.Config" -> v2rayBean.mekyaKcpHeaderType = "srtp"
                                            "types.v2fly.org/v2ray.core.transport.internet.headers.utp.Config" -> v2rayBean.mekyaKcpHeaderType = "utp"
                                            "types.v2fly.org/v2ray.core.transport.internet.headers.wechat.VideoConfig" -> v2rayBean.mekyaKcpHeaderType = "wechat-video"
                                            "types.v2fly.org/v2ray.core.transport.internet.headers.tls.PacketConfig" -> v2rayBean.mekyaKcpHeaderType = "dtls"
                                            "types.v2fly.org/v2ray.core.transport.internet.headers.wireguard.WireguardConfig" -> v2rayBean.mekyaKcpHeaderType = "wireguard"
                                            else -> return proxies
                                        }
                                    }
                                }
                            }
                            "hysteria2" -> {
                                v2rayBean.type = "hysteria2"
                                streamSettings.getObject("transportSettings")?.also { transportSettings ->
                                    transportSettings["password"]?.toString()?.also {
                                        v2rayBean.hy2Password = it
                                    }
                                    /*(transportSettings["congestion"] as? JSONObject)?.also { congestion ->
                                        (congestion["up_mbps"] as? Int ?: congestion["upMbps"] as? Int)?.also {
                                            v2rayBean.hy2UpMbps = it
                                        }
                                        (congestion["down_mbps"] as? Int ?: congestion["downMbps"] as? Int)?.also {
                                            v2rayBean.hy2DownMbps = it
                                        }
                                    }*/
                                }
                            }
                            else -> return proxies
                        }
                    }
                }

                (outbound["settings"] as? JSONObject)?.also { settings ->
                    if (settings.containsKey("servers") || settings.containsKey("vnext")) { // jsonv4
                        return proxies
                    }
                    settings["address"]?.toString()?.also {
                        v2rayBean.serverAddress = it
                    } ?: return proxies
                    settings["port"]?.toString()?.toInt()?.also {
                        v2rayBean.serverPort = it
                    } ?: return proxies
                    when (type) {
                        "shadowsocks" -> {
                            v2rayBean as ShadowsocksBean
                            settings["method"]?.toString()?.lowercase()?.also {
                                v2rayBean.method = when (it) {
                                    in supportedShadowsocksMethod -> it
                                    "aes_128_gcm", "aead_aes_128_gcm" -> "aes-128-gcm"
                                    "aes_192_gcm", "aead_aes_192_gcm" -> "aes-192-gcm"
                                    "aes_256_gcm", "aead_aes_256_gcm" -> "aes-256-gcm"
                                    "chacha20_poly1305", "aead_chacha20_poly1305", "chacha20-poly1305" -> "chacha20-ietf-poly1305"
                                    "xchacha20_poly1305", "aead_xchacha20_poly1305", "xchacha20-poly1305" -> "xchacha20-ietf-poly1305"
                                    "plain" -> "none"
                                    else -> return proxies
                                }
                            }
                            settings["password"]?.toString()?.also {
                                v2rayBean.password = it
                            }
                        }
                        "trojan" -> {
                            v2rayBean as TrojanBean
                            settings["password"]?.toString()?.also {
                                v2rayBean.password = it
                            }
                        }
                        "vmess" -> {
                            v2rayBean as VMessBean
                            settings["uuid"]?.toString()?.also {
                                v2rayBean.uuid = it
                            }
                        }
                        "vless" -> {
                            v2rayBean as VLESSBean
                            settings["uuid"]?.toString()?.also {
                                v2rayBean.uuid = it
                            }
                        }
                        "shadowsocks2022" -> {
                            v2rayBean as ShadowsocksBean
                            settings["method"]?.toString()?.also {
                                if (it !in supportedShadowsocks2022Method)
                                    return proxies
                                v2rayBean.method = it
                            }
                            settings["psk"]?.toString()?.also { psk ->
                                v2rayBean.password = psk
                                (settings["ipsk"] as? List<String>)?.also { ipsk ->
                                    v2rayBean.password = ipsk.joinToString(":") + ":" + psk

                                }
                            }
                        }
                    }
                    proxies.add(v2rayBean)
                }
            }
            "hysteria2" -> {
                val hysteria2Bean = Hysteria2Bean().apply {
                    outbound.getString("tag")?.also {
                        name = it
                    }
                }
                outbound.getObject("settings")?.also { settings ->
                    (settings["server"] as? List<JSONObject>)?.get(0)?.also { server ->
                        server["address"]?.toString()?.also {
                            hysteria2Bean.serverAddress = it
                        } ?: return proxies
                        (server["port"]?.toString()?.toInt())?.also {
                            hysteria2Bean.serverPorts = it.toString()
                        } ?: return proxies
                    }
                } ?: return proxies
                outbound.getObject("streamSettings")?.also { streamSettings ->
                    if (streamSettings.getString("security") != "tls") {
                        return proxies
                    }
                    if (streamSettings.getString("transport") != "hysteria2") {
                        return proxies
                    }
                    streamSettings.getObject("securitySettings")?. also { securitySettings ->
                        (securitySettings["serverName"]?.toString() ?: securitySettings["server_name"]?.toString())?.also {
                            hysteria2Bean.sni = it
                        }
                    }
                    streamSettings.getObject("transportSettings")?.also { transportSettings ->
                        transportSettings["password"]?.toString()?.also {
                            hysteria2Bean.auth = it
                        }
                        /*(transportSettings["congestion"] as? JSONObject)?.also { congestion ->
                            (congestion["up_mbps"]?.toString()?.toInt()?: congestion["upMbps"]?.toString()?.toInt())?.also {
                                hysteria2Bean.uploadMbps = it
                            }
                            (congestion["down_mbps"]?.toString()?.toInt() ?: congestion["downMbps"]?.toString()?.toInt())?.also {
                                hysteria2Bean.downloadMbps = it
                            }
                        }*/
                    }
                    proxies.add(hysteria2Bean)
                }
            }
        }
        return proxies
    }

    @Suppress("UNCHECKED_CAST")
    private fun parseClashProxies(proxy: Map<String, Any?>): List<AbstractBean> {
        val proxies = ArrayList<AbstractBean>()
        // Note: YAML numbers parsed as "Long"
        when (proxy["type"]) {
            "socks5" -> {
                proxies.add(SOCKSBean().apply {
                    serverAddress = proxy["server"]?.toString() ?: return proxies
                    serverPort = proxy["port"]?.toString()?.toIntOrNull() ?: return proxies
                    username = proxy["username"]?.toString()
                    password = proxy["password"]?.toString()
                    if (proxy["tls"] as? Boolean == true) {
                        security = "tls"
                        if (proxy["skip-cert-verify"] as? Boolean == true) {
                            allowInsecure = true
                        }
                    }
                    name = proxy["name"]?.toString()
                })
            }
            "http" -> {
                proxies.add(HttpBean().apply {
                    serverAddress = proxy["server"]?.toString() ?: return proxies
                    serverPort = proxy["port"]?.toString()?.toIntOrNull() ?: return proxies
                    username = proxy["username"]?.toString()
                    password = proxy["password"]?.toString()
                    if (proxy["tls"] as? Boolean == true) {
                        security = "tls"
                        sni = proxy["sni"]?.toString()
                        if (proxy["skip-cert-verify"] as? Boolean == true) {
                            allowInsecure = true
                        }
                    }
                    name = proxy["name"]?.toString()
                })
            }
            "ss" -> {
                var pluginStr = ""
                if (proxy.contains("plugin")) {
                    val opts = proxy["plugin-opts"] as? Map<String, Any?>
                    val pluginOpts = PluginOptions()
                    fun put(clash: String, origin: String = clash) {
                        opts?.get(clash)?.let {
                            pluginOpts[origin] = it.toString()
                        }
                    }
                    when (proxy["plugin"]) {
                        "obfs" -> {
                            pluginOpts.id = "obfs-local"
                            put("mode", "obfs")
                            put("host", "obfs-host")
                        }
                        "v2ray-plugin" -> {
                            pluginOpts.id = "v2ray-plugin"
                            put("mode")
                            if (opts?.get("tls") as? Boolean == true) {
                                pluginOpts["tls"] = null
                            }
                            put("host")
                            put("path")
                            if (opts?.get("mux") as? Boolean == true) {
                                pluginOpts["mux"] = "8"
                            }
                            if (opts?.get("v2ray-http-upgrade") as? Boolean == true) {
                                return proxies
                            }
                        }
                        else -> return proxies
                    }
                    pluginStr = pluginOpts.toString(false)
                }
                proxies.add(ShadowsocksBean().apply {
                    serverAddress = proxy["server"]?.toString() ?: return proxies
                    serverPort = proxy["port"]?.toString()?.toIntOrNull() ?: return proxies
                    password = proxy["password"]?.toString()
                    method = when (val cipher = proxy["cipher"] as? String) {
                        "dummy" -> "none"
                        in supportedShadowsocksMethod -> cipher
                        else -> return proxies
                    }
                    plugin = pluginStr
                    name = proxy["name"]?.toString()
                    fixInvalidParams()
                })
            }
            "vmess", "vless", "trojan" -> {
                val bean = when (proxy["type"] as String) {
                    "vmess" -> VMessBean()
                    "vless" -> VLESSBean()
                    "trojan" -> TrojanBean()
                    else -> error("impossible")
                }.apply {
                    serverAddress = proxy["server"]?.toString() ?: return proxies
                    serverPort = proxy["port"]?.toString()?.toIntOrNull() ?: return proxies
                }
                if (bean is TrojanBean) {
                    bean.security = "tls"
                }
                for (opt in proxy) {
                    when (opt.key) {
                        "name" -> bean.name = opt.value?.toString()
                        "password" -> if (bean is TrojanBean) bean.password = opt.value?.toString()
                        "uuid" -> if (bean is VMessBean || bean is VLESSBean) {
                            opt.value?.toString()?.takeIf { it.isNotEmpty() }?.also {
                                bean.uuid = try {
                                    UUID.fromString(it).toString(false)
                                } catch (_: Exception) {
                                    uuid5(it)
                                }
                            }
                        }
                        "alterId" -> if (bean is VMessBean) bean.alterId = opt.value?.toString()?.toIntOrNull()
                        "cipher" -> {
                            if (bean is VMessBean) {
                                bean.encryption = when (val cipher = opt.value as? String) {
                                    in supportedVmessMethod -> cipher
                                    else -> return proxies
                                }
                            }
                        }
                        "flow" -> if (bean is VLESSBean && (opt.value as? String)?.startsWith("xtls-rprx-vision") == true) {
                            bean.flow = "xtls-rprx-vision-udp443"
                            bean.packetEncoding = "xudp"
                        } else return proxies
                        "authenticated-length" -> if (bean is VMessBean) bean.experimentalAuthenticatedLength = opt.value as? Boolean == true
                        "packet-encoding" -> {
                            when (bean) {
                                is VMessBean -> bean.packetEncoding = when ((opt.value as? String)) {
                                    "packetaddr", "packet" -> "packet"
                                    "xudp" -> "xudp"
                                    else -> "none"
                                }
                                is VLESSBean -> bean.packetEncoding = when ((opt.value as? String)) {
                                    "packetaddr", "packet" -> "packet"
                                    else -> "xudp"
                                }
                            }
                        }
                        "packet-addr" -> if (bean is VMessBean || bean is VLESSBean && opt.value as? Boolean == true) bean.packetEncoding = "packet"
                        "xudp" -> if (bean is VMessBean || bean is VLESSBean && opt.value as? Boolean == true) bean.packetEncoding = "xudp"
                        "tls" -> if (bean is VMessBean || bean is VLESSBean) {
                            bean.security = if (opt.value as? Boolean == true) "tls" else "none"
                        }
                        "servername" -> if (bean is VMessBean || bean is VLESSBean) bean.sni = opt.value?.toString()
                        "sni" -> if (bean is TrojanBean) bean.sni = opt.value?.toString()
                        "alpn" -> bean.alpn = (opt.value as? List<Any>)?.joinToString("\n")
                        "skip-cert-verify" -> bean.allowInsecure = opt.value as? Boolean == true
                        "reality-opts" -> (opt.value as? Map<String, Any?>)?.also {
                            for (realityOpt in it) {
                                bean.security = "reality"
                                when (realityOpt.key) {
                                    "public-key" -> bean.realityPublicKey = realityOpt.value?.toString()
                                    "short-id" -> bean.realityShortId = realityOpt.value?.toString()
                                }
                            }
                        }
                        "network" -> {
                            when (opt.value) {
                                "h2" -> bean.type = "http"
                                "http" -> {
                                    bean.type = "tcp"
                                    bean.headerType = "http"
                                }
                                "ws", "grpc" -> bean.type = opt.value as String
                                else -> {
                                    // Do not `return proxies` here. Fuck those non-standard configs.
                                    bean.type = "tcp"
                                }
                            }
                        }
                        "ws-opts" -> (opt.value as? Map<String, Any?>)?.also {
                            for (wsOpt in it) {
                                when (wsOpt.key) {
                                    "headers" -> (wsOpt.value as? Map<Any, Any?>)?.forEach { (key, value) ->
                                        when (key.toString().lowercase()) {
                                            "host" -> {
                                                bean.host = value?.toString()
                                            }
                                        }
                                    }
                                    "path" -> {
                                        bean.path = wsOpt.value?.toString()
                                    }
                                    "max-early-data" -> {
                                        bean.maxEarlyData = wsOpt.value?.toString()?.toIntOrNull()
                                    }
                                    "early-data-header-name" -> {
                                        bean.earlyDataHeaderName = wsOpt.value?.toString()
                                    }
                                    "v2ray-http-upgrade" -> {
                                        if (wsOpt.value as? Boolean == true) {
                                            bean.type = "httpupgrade"
                                        }
                                    }
                                }
                            }
                        }
                        "h2-opts" -> (opt.value as? Map<String, Any?>)?.also {
                            for (h2Opt in it) {
                                when (h2Opt.key) {
                                    "host" -> bean.host = (h2Opt.value as? List<Any>)?.joinToString("\n")
                                    "path" -> bean.path = h2Opt.value?.toString()
                                }
                            }
                        }
                        "http-opts" -> (opt.value as? Map<String, Any?>)?.also {
                            for (httpOpt in it) {
                                when (httpOpt.key) {
                                    "path" -> bean.path = (httpOpt.value as? List<Any>)?.joinToString("\n")
                                    "headers" -> {
                                        (httpOpt.value as? Map<Any, List<Any>>)?.forEach { (key, value) ->
                                            when (key.toString().lowercase()) {
                                                "host" -> {
                                                    bean.host = value.joinToString("\n")
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        "grpc-opts" -> (opt.value as? Map<String, Any?>)?.also {
                            for (grpcOpt in it) {
                                when (grpcOpt.key) {
                                    "grpc-service-name" -> bean.grpcServiceName = grpcOpt.value?.toString()
                                }
                            }
                        }
                    }
                }
                proxies.add(bean)
            }
            "ssr" -> {
                proxies.add(ShadowsocksRBean().apply {
                    serverAddress = proxy["server"]?.toString() ?: return proxies
                    serverPort = proxy["port"]?.toString()?.toIntOrNull() ?: return proxies
                    method = when (val cipher = proxy["cipher"] as? String) {
                        "dummy" -> "none"
                        in supportedShadowsocksRMethod -> cipher
                        else -> return proxies
                    }
                    password = proxy["password"]?.toString()
                    obfs = when (val it = proxy["obfs"] as? String) {
                        "tls1.2_ticket_fastauth" -> "tls1.2_ticket_auth"
                        in supportedShadowsocksRObfs -> it
                        else -> return proxies
                    }
                    obfsParam = proxy["obfs-param"]?.toString()
                    protocol = when (val it = proxy["protocol"] as? String) {
                        in supportedShadowsocksRProtocol -> it
                        else -> return proxies
                    }
                    protocolParam = proxy["protocol-param"]?.toString()
                    name = proxy["name"]?.toString()
                })
            }
            "ssh" -> {
                val bean = SSHBean().apply {
                    serverAddress = proxy["server"]?.toString() ?: return proxies
                    serverPort = proxy["port"]?.toString()?.toIntOrNull() ?: return proxies
                }
                for (opt in proxy) {
                    when (opt.key) {
                        "name" -> bean.name = opt.value?.toString()
                        "username" -> bean.username = opt.value?.toString()
                        "password" -> {
                            bean.password = opt.value?.toString()
                            bean.authType = SSHBean.AUTH_TYPE_PASSWORD
                        }
                        "private-key" -> {
                            bean.privateKey = opt.value?.toString()
                            bean.authType = SSHBean.AUTH_TYPE_PRIVATE_KEY
                        }
                        "private-key-passphrase" -> bean.privateKeyPassphrase = opt.value?.toString()
                        "host-key" -> (opt.value as? List<Any>)?.also {
                            bean.publicKey = it.joinToString("\n")
                        }
                    }
                }
                proxies.add(bean)
            }
            "hysteria" -> {
                proxies.add(HysteriaBean().apply {
                    serverAddress = proxy["server"]?.toString() ?: return proxies
                    serverPorts = proxy["ports"]?.toString()?.takeIf { it.isValidHysteriaPort() }
                        ?: proxy["port"]?.toString()?.toIntOrNull()?.toString() ?: return proxies
                    protocol = when (proxy["protocol"] as? String ?: proxy["obfs-protocol"] as? String) {
                        "faketcp" -> HysteriaBean.PROTOCOL_FAKETCP
                        "wechat-video" -> HysteriaBean.PROTOCOL_WECHAT_VIDEO
                        "udp" -> HysteriaBean.PROTOCOL_UDP
                        else -> return proxies
                    }
                    authPayloadType = HysteriaBean.TYPE_NONE
                    proxy["auth-str"]?.also {
                        authPayloadType = HysteriaBean.TYPE_STRING
                        authPayload = it.toString()
                    }
                    proxy["auth"]?.toString()?.takeIf { it.isNotEmpty() }?.also {
                        authPayloadType = HysteriaBean.TYPE_BASE64
                        authPayload = it
                    }
                    uploadMbps = (proxy["up"]?.toString())?.toMegaBitsPerSecond() ?: proxy["up-speed"]?.toString()?.toIntOrNull()
                    downloadMbps = (proxy["down"]?.toString())?.toMegaBitsPerSecond() ?: proxy["down-speed"]?.toString()?.toIntOrNull()
                    sni = proxy["sni"]?.toString()
                    alpn = (proxy["alpn"] as? List<Any>)?.get(0)?.toString()
                    allowInsecure = proxy["skip-cert-verify"] as? Boolean == true
                    obfuscation = proxy["obfs"]?.toString()?.takeIf { it.isNotEmpty() }
                    hopInterval = proxy["hop-interval"]?.toString()?.toIntOrNull()
                    name = proxy["name"]?.toString()
                })
            }
            "hysteria2" -> {
                proxies.add(Hysteria2Bean().apply {
                    serverAddress = proxy["server"]?.toString() ?: return proxies
                    serverPorts = proxy["ports"]?.toString()?.takeIf { it.isValidHysteriaPort() }
                        ?: proxy["port"]?.toString()?.toIntOrNull()?.toString() ?: return proxies
                    auth = proxy["password"]?.toString()
                    // uploadMbps = (proxy["up"]?.toString())?.toMegaBitsPerSecond()
                    // downloadMbps = (proxy["down"]?.toString())?.toMegaBitsPerSecond()
                    sni = proxy["sni"]?.toString()
                    // alpn = (proxy["alpn"] as? List<Any>)?.joinToString("\n")
                    allowInsecure = proxy["skip-cert-verify"] as? Boolean == true
                    when (proxy["obfs"] as? String) {
                        "" -> {}
                        "salamander" -> {
                            obfs = proxy["obfs-password"]?.toString()
                        }
                        else -> return proxies
                    }
                    hopInterval = proxy["hop-interval"]?.toString()?.toIntOrNull()
                    name = proxy["name"]?.toString()
                })
            }
            "tuic" -> {
                if (proxy["token"] != null) {
                    proxies.add(TuicBean().apply {
                        serverAddress = proxy["ip"]?.toString() ?: proxy["server"]?.toString() ?: return proxies
                        serverPort = proxy["port"]?.toString()?.toIntOrNull() ?: return proxies
                        token = proxy["token"]?.toString()
                        udpRelayMode = when (val mode = proxy["udp-relay-mode"] as? String) {
                            in supportedTuicRelayMode -> mode
                            else -> "native"
                        }
                        congestionController = when (val controller = proxy["congestion-controller"] as? String) {
                            in supportedTuicCongestionControl -> controller
                            else -> "cubic"
                        }
                        disableSNI = proxy["disable-sni"] as? Boolean == true
                        reduceRTT = proxy["reduce-rtt"] as? Boolean == true
                        // allowInsecure = proxy["skip-cert-verify"] as? Boolean == true
                        sni = proxy["sni"]?.toString() ?: if (proxy["ip"]?.toString() != null) proxy["server"]?.toString() else null
                        // https://github.com/MetaCubeX/mihomo/blob/d5243adf8911563677d3bd190b82623c93e554b7/adapter/outbound/tuic.go#L174-L178
                        alpn = if (!proxy.containsKey("alpn")) "h3" else (proxy["alpn"] as? List<Any>)?.joinToString("\n")
                        name = proxy["name"]?.toString()
                    })
                } else {
                    proxies.add(Tuic5Bean().apply {
                        serverAddress = proxy["ip"]?.toString() ?: proxy["server"]?.toString() ?: return proxies
                        serverPort = proxy["port"]?.toString()?.toIntOrNull() ?: return proxies
                        uuid = proxy["uuid"] as? String
                        password = proxy["password"]?.toString()
                        udpRelayMode = when (val mode = proxy["udp-relay-mode"] as? String) {
                            in supportedTuic5RelayMode -> mode
                            else -> "native"
                        }
                        congestionControl = when (val controller = proxy["congestion-controller"] as? String) {
                            in supportedTuic5CongestionControl -> controller
                            else -> "cubic"
                        }
                        disableSNI = proxy["disable-sni"] as? Boolean == true
                        zeroRTTHandshake = proxy["reduce-rtt"] as? Boolean == true
                        allowInsecure = proxy["skip-cert-verify"] as? Boolean == true
                        sni =  proxy["sni"]?.toString() ?: if (proxy["ip"]?.toString() != null) proxy["server"]?.toString() else null
                        // https://github.com/MetaCubeX/mihomo/blob/d5243adf8911563677d3bd190b82623c93e554b7/adapter/outbound/tuic.go#L174-L178
                        alpn = if (!proxy.containsKey("alpn")) "h3" else (proxy["alpn"] as? List<Any>)?.joinToString("\n")
                        name = proxy["name"]?.toString()
                    })
                }
            }
            "wireguard" -> {
                val wireGuardBean = WireGuardBean().apply {
                    serverAddress = proxy["server"]?.toString()
                    serverPort = proxy["port"]?.toString()?.toIntOrNull()
                    privateKey = proxy["private-key"] as? String
                    peerPublicKey = proxy["public-key"] as? String
                    peerPreSharedKey = proxy["pre-shared-key"] as? String
                        ?: proxy["preshared-key"] as? String // "preshared-key" from Clash Premium
                    mtu = (proxy["mtu"]?.toString()?.toIntOrNull())?.takeIf { it > 0 } ?: 1408
                    localAddress = listOfNotNull(proxy["ip"] as? String, proxy["ipv6"] as? String).joinToString("\n")
                    keepaliveInterval = proxy["persistent-keepalive"]?.toString()?.toIntOrNull()?.takeIf { it > 0 }
                    name = proxy["name"]?.toString()
                    (proxy["reserved"] as? List<Map<String, Any>>)?.also {
                        if (it.size == 3) {
                            reserved = listOf(it[0].toString(), it[1].toString(), it[2].toString()).joinToString(",")
                        }
                    } ?: {
                        Base64.decode(proxy["reserved"]?.toString())?.also {
                            if (it.size == 3) {
                                reserved = listOf(it[0].toUByte().toInt().toString(), it[1].toUByte().toInt().toString(), it[2].toUByte().toInt().toString()).joinToString(",")
                            }
                        }
                    }
                }
                if (proxy["server"] != null && proxy["port"] != null) {
                    proxies.add(wireGuardBean)
                }
                (proxy["peers"] as? List<Map<String, Any>>)?.forEach {
                    if (it["server"] != null && it["port"] != null) {
                        proxies.add(wireGuardBean.applyDefaultValues().clone().apply {
                            serverAddress = it["server"]?.toString()
                            serverPort = it["port"]?.toString()?.toIntOrNull()
                            peerPublicKey = it["public-key"] as? String
                            peerPreSharedKey = it["pre-shared-key"] as? String
                            (it["reserved"] as? List<Map<String, Any>>)?.also {
                                if (it.size == 3) {
                                    reserved = listOf(it[0].toString(), it[1].toString(), it[2].toString()).joinToString(",")
                                }
                            } ?: {
                                Base64.decode(it["reserved"]?.toString())?.also {
                                    if (it.size == 3) {
                                        reserved = listOf(it[0].toUByte().toInt().toString(), it[1].toUByte().toInt().toString(), it[2].toUByte().toInt().toString()).joinToString(",")
                                    }
                                }
                            }
                        })
                    }
                }
            }
            "mieru" -> {
                val bean = MieruBean().apply {
                    serverAddress = proxy["server"]?.toString() ?: return proxies
                    // Why yet another protocol containing port-range? Let us use the first port only for now.
                    serverPort = proxy["port"]?.toString()?.toIntOrNull() ?: (proxy["port-range"]?.toString())?.substringBefore("-")?.toIntOrNull() ?: return proxies
                }
                for (opt in proxy) {
                    when (opt.key) {
                        "name" -> bean.name = opt.value?.toString()
                        "username" -> bean.username = opt.value?.toString()
                        "password" -> bean.password = opt.value?.toString()
                        "transport" -> when (opt.value) {
                            "TCP" -> bean.protocol = MieruBean.PROTOCOL_TCP
                            "UDP" -> bean.protocol = MieruBean.PROTOCOL_UDP // not implemented as of mihomo v1.19.0
                            else -> return proxies
                        }
                        "multiplexing" -> when (opt.value) {
                            "MULTIPLEXING_OFF" -> bean.multiplexingLevel = MieruBean.MULTIPLEXING_OFF
                            "MULTIPLEXING_LOW" -> bean.multiplexingLevel = MieruBean.MULTIPLEXING_LOW
                            "MULTIPLEXING_MIDDLE" -> bean.multiplexingLevel = MieruBean.MULTIPLEXING_MIDDLE
                            "MULTIPLEXING_HIGH" -> bean.multiplexingLevel = MieruBean.MULTIPLEXING_HIGH
                            else -> bean.multiplexingLevel = MieruBean.MULTIPLEXING_LOW
                        }
                    }
                }
                proxies.add(bean)
            }
            "anytls" -> {
                val bean = AnyTLSBean().apply {
                    serverAddress = proxy["server"]?.toString() ?: return proxies
                    serverPort = proxy["port"]?.toString()?.toIntOrNull() ?: return proxies
                    security = "tls"
                }
                for (opt in proxy) {
                    when (opt.key) {
                        "name" -> bean.name = opt.value?.toString()
                        "password" -> bean.password = opt.value?.toString()
                        "sni" -> bean.sni = opt.value?.toString()
                        "skip-cert-verify" -> bean.allowInsecure = opt.value as? Boolean
                        "alpn" -> bean.alpn = (opt.value as? List<Any>)?.joinToString("\n")
                    }
                }
                proxies.add(bean)
            }
        }
        return proxies
    }
}