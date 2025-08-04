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

import cn.hutool.core.codec.Base64
import cn.hutool.core.lang.UUID
import com.github.shadowsocks.plugin.PluginOptions
import io.nekohasekai.sagernet.fmt.AbstractBean
import io.nekohasekai.sagernet.fmt.anytls.AnyTLSBean
import io.nekohasekai.sagernet.fmt.http.HttpBean
import io.nekohasekai.sagernet.fmt.hysteria.HysteriaBean
import io.nekohasekai.sagernet.fmt.hysteria2.Hysteria2Bean
import io.nekohasekai.sagernet.fmt.mieru.MieruBean
import io.nekohasekai.sagernet.fmt.shadowsocks.ShadowsocksBean
import io.nekohasekai.sagernet.fmt.shadowsocks.supportedShadowsocksMethod
import io.nekohasekai.sagernet.fmt.shadowsocksr.ShadowsocksRBean
import io.nekohasekai.sagernet.fmt.shadowsocksr.supportedShadowsocksRMethod
import io.nekohasekai.sagernet.fmt.shadowsocksr.supportedShadowsocksRObfs
import io.nekohasekai.sagernet.fmt.shadowsocksr.supportedShadowsocksRProtocol
import io.nekohasekai.sagernet.fmt.socks.SOCKSBean
import io.nekohasekai.sagernet.fmt.ssh.SSHBean
import io.nekohasekai.sagernet.fmt.trojan.TrojanBean
import io.nekohasekai.sagernet.fmt.trojan_go.TrojanGoBean
import io.nekohasekai.sagernet.fmt.tuic.TuicBean
import io.nekohasekai.sagernet.fmt.tuic.supportedTuicCongestionControl
import io.nekohasekai.sagernet.fmt.tuic.supportedTuicRelayMode
import io.nekohasekai.sagernet.fmt.tuic5.Tuic5Bean
import io.nekohasekai.sagernet.fmt.tuic5.supportedTuic5CongestionControl
import io.nekohasekai.sagernet.fmt.tuic5.supportedTuic5RelayMode
import io.nekohasekai.sagernet.fmt.v2ray.VLESSBean
import io.nekohasekai.sagernet.fmt.v2ray.VMessBean
import io.nekohasekai.sagernet.fmt.v2ray.supportedVmessMethod
import io.nekohasekai.sagernet.fmt.wireguard.WireGuardBean
import io.nekohasekai.sagernet.ktx.*
import libcore.Libcore

fun String.toUIntOrNull(): Int? {
    // mimic Mihomo's custom int parser
    if (this.contains(":")) return null
    if (this.contains("-")) return null
    val newStr = this.lowercase().removePrefix("+")
    if (newStr.contains("+")) return null
    if (newStr.startsWith("0x")) {
        return newStr.removePrefix("0x").replace("_", "").toIntOrNull(16)
    }
    if (newStr.startsWith("0b")) {
        return newStr.removePrefix("0b").replace("_", "").toIntOrNull(2)
    }
    if (newStr.startsWith("0o")) {
        return newStr.removePrefix("0o").replace("_", "").toIntOrNull(8)
    }
    if (newStr.startsWith("0")) {
        return newStr.removePrefix("0").replace("_", "").toIntOrNull(8)
    }
    if (newStr.startsWith("_")) {
        return null
    }
    return newStr.replace("_", "").toIntOrNull()
}

@Suppress("UNCHECKED_CAST")
fun parseClashProxies(proxy: Map<String, Any?>): List<AbstractBean> {
    when (proxy["type"]) {
        "socks5" -> {
            return listOf(SOCKSBean().apply {
                serverAddress = proxy["server"]?.toString() ?: return listOf()
                serverPort = proxy["port"]?.toString()?.toUIntOrNull() ?: return listOf()
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
            return listOf(HttpBean().apply {
                serverAddress = proxy["server"]?.toString() ?: return listOf()
                serverPort = proxy["port"]?.toString()?.toUIntOrNull() ?: return listOf()
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
                            return listOf()
                        }
                    }
                    "", null -> {}
                    else -> return listOf()
                }
                pluginStr = pluginOpts.toString(false)
            }
            return listOf(ShadowsocksBean().apply {
                serverAddress = proxy["server"]?.toString() ?: return listOf()
                serverPort = proxy["port"]?.toString()?.toUIntOrNull() ?: return listOf()
                password = proxy["password"]?.toString()
                method = when (val cipher = (proxy["cipher"] as? String)?.lowercase()) {
                    "dummy" -> "none"
                    "aead_aes_128_gcm" -> "aes-128-gcm"
                    "aead_aes_192_gcm" -> "aes-192-gcm"
                    "aead_aes_256_gcm" -> "aes-256-gcm"
                    "aead_chacha20_poly1305" -> "chacha20-ietf-poly1305"
                    "aead_xchacha20_poly1305" -> "xchacha20-ietf-poly1305"
                    in supportedShadowsocksMethod -> cipher
                    else -> return listOf()
                }
                plugin = pluginStr
                name = proxy["name"]?.toString()
            })
        }
        "vmess", "vless", "trojan" -> {
            val bean = when (proxy["type"] as String) {
                "vmess" -> VMessBean()
                "vless" -> VLESSBean()
                "trojan" -> TrojanBean()
                else -> error("impossible")
            }.apply {
                serverAddress = proxy["server"]?.toString() ?: return listOf()
                serverPort = proxy["port"]?.toString()?.toUIntOrNull() ?: return listOf()
                name = proxy["name"]?.toString()
            }

            if (bean is TrojanBean) {
                when (val network = proxy["network"]?.toString()) {
                    "ws", "grpc" -> bean.type = network
                    else -> bean.type = "tcp"
                }
            } else {
                when (val network = proxy["network"]?.toString()) {
                    "h2" -> bean.type = "http"
                    "http" -> {
                        bean.type = "tcp"
                        bean.headerType = "http"
                    }
                    "ws", "grpc" -> bean.type = network
                    else -> bean.type = "tcp"
                }
            }

            if (bean is TrojanBean) {
                bean.security = "tls"
                bean.sni = proxy["sni"]?.toString()
                bean.password = proxy["password"]?.toString()
            } else {
                bean.security = if (proxy["tls"] as? Boolean == true) "tls" else "none"
                if (bean.security == "tls") {
                    bean.sni = proxy["servername"]?.toString()
                }
                proxy["uuid"]?.toString()?.takeIf { it.isNotEmpty() }?.also {
                    bean.uuid = try {
                        UUID.fromString(it).toString()
                    } catch (_: Exception) {
                        uuid5(it)
                    }
                }
            }
            if (bean.security == "tls") {
                bean.alpn = (proxy["alpn"] as? List<Any>)?.joinToString("\n")
                bean.allowInsecure = proxy["skip-cert-verify"] as? Boolean == true
            }

            if (bean is VMessBean) {
                bean.alterId = proxy["alterId"]?.toString()?.toUIntOrNull()
                bean.encryption = when (val cipher = proxy["cipher"] as? String) {
                    in supportedVmessMethod -> cipher
                    else -> return listOf()
                }
                bean.experimentalAuthenticatedLength = proxy["authenticated-length"] as? Boolean == true
                var isPacket = false
                var isXUDP = false
                if (proxy["packet-addr"] as? Boolean == true) {
                    isPacket = true
                    isXUDP = false
                }
                if (proxy["xudp"] as? Boolean == true) {
                    isXUDP = true
                    isPacket = false
                }
                when ((proxy["packet-encoding"] as? String)) {
                    "packetaddr", "packet" -> {
                        isPacket = true
                        isXUDP = false
                    }
                    "xudp" -> {
                        isXUDP = true
                        isPacket = false
                    }
                }
                bean.packetEncoding = when {
                    isPacket -> "packet"
                    isXUDP -> "xudp"
                    else -> "none"
                }
            }

            if (bean is VLESSBean) {
                var isPacket = false
                var isXUDP = true
                if (proxy["packet-addr"] as? Boolean == true) {
                    isPacket = true
                    isXUDP = false
                }
                if (proxy["xudp"] as? Boolean == true) {
                    isXUDP = true
                    isPacket = false
                }
                when (proxy["packet-encoding"] as? String) {
                    "packetaddr", "packet" -> {
                        isPacket = true
                        isXUDP = false
                    }
                    "xudp" -> {
                        isXUDP = true
                        isPacket = false
                    }
                }
                bean.packetEncoding = when {
                    isPacket -> "packet"
                    isXUDP -> "xudp"
                    else -> "xudp"
                }
                if (bean.type != "ws") {
                    (proxy["flow"]?.toString())?.takeIf { it.isNotEmpty() }?.also {
                        if (it.startsWith("xtls-rprx-vision")) {
                            bean.flow = "xtls-rprx-vision-udp443"
                            bean.packetEncoding = "xudp"
                        } else return listOf()
                    }
                }
            }

            (proxy["reality-opts"] as? Map<String, Any?>)?.also {
                for (realityOpt in it) {
                    bean.security = "reality"
                    when (realityOpt.key) {
                        "public-key" -> bean.realityPublicKey = realityOpt.value?.toString()
                        "short-id" -> bean.realityShortId = realityOpt.value?.toString()
                    }
                }
            }

            if (bean.type == "tcp" && bean.headerType != null && bean.headerType == "http") {
                (proxy["http-opts"] as? Map<String, Any?>)?.also {
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
            }
            if (bean.type == "ws") {
                if (bean is TrojanBean && (bean.security == "tls" || bean.security == "reality") && !bean.sni.isNullOrEmpty()) {
                    bean.host = bean.sni
                }
                (proxy["ws-opts"] as? Map<String, Any?>)?.also { wsOpts ->
                    for (wsOpt in wsOpts) {
                        when (wsOpt.key) {
                            "headers" -> (wsOpt.value as? Map<Any, Any?>)?.forEach { (key, value) ->
                                when (key.toString().lowercase()) {
                                    "host" -> {
                                        value?.toString()?.takeIf { it.isNotEmpty() }?.also {
                                            bean.host = it
                                            if (bean !is TrojanBean && (bean.security == "tls" || bean.security == "reality") && bean.sni.isNullOrEmpty()) {
                                                bean.sni = it
                                            }
                                        }
                                    }
                                }
                            }
                            "path" -> {
                                bean.path = wsOpt.value?.toString()
                            }
                            "max-early-data" -> {
                                bean.maxEarlyData = wsOpt.value?.toString()?.toUIntOrNull()
                            }
                            "early-data-header-name" -> {
                                bean.earlyDataHeaderName = wsOpt.value?.toString()
                            }
                            "v2ray-http-upgrade" -> {
                                if (wsOpt.value as? Boolean == true) {
                                    bean.type = "httpupgrade"
                                    bean.maxEarlyData = null
                                    bean.earlyDataHeaderName = null
                                }
                            }
                        }
                    }
                    if (!bean.path.isNullOrEmpty()) {
                        try {
                            val u = Libcore.parseURL(bean.path)
                            u.queryParameter("ed")?.also { ed ->
                                u.deleteQueryParameter("ed")
                                bean.path = u.string
                                (ed.toIntOrNull())?.also {
                                    bean.maxEarlyData = it
                                }
                                bean.earlyDataHeaderName = "Sec-WebSocket-Protocol"
                            }
                        } catch (_: Exception) {}
                    }
                }
            }
            if (bean.type == "http") {
                (proxy["h2-opts"] as? Map<String, Any?>)?.also {
                    for (h2Opt in it) {
                        when (h2Opt.key) {
                            "host" -> bean.host = (h2Opt.value as? List<Any>)?.joinToString("\n")
                            "path" -> bean.path = h2Opt.value?.toString()
                        }
                    }
                }
            }
            if (bean.type == "grpc") {
                (proxy["grpc-opts"] as? Map<String, Any?>)?.also {
                    for (grpcOpt in it) {
                        when (grpcOpt.key) {
                            "grpc-service-name" -> bean.grpcServiceName = grpcOpt.value?.toString()
                        }
                    }
                }
            }

            if (bean is TrojanBean) {
                (proxy["ss-opts"] as? Map<String, Any?>)?.also {
                    if (it["enabled"] as? Boolean == true) {
                        if (bean.security != "tls") {
                            // unsupported
                            return listOf()
                        }
                        val ssMethod = when (val method = (it["method"] as? String)?.lowercase()) {
                            "aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305" -> method
                            "aead_aes_128_gcm", "" -> "aes-128-gcm"
                            "aead_aes_256_gcm" -> "aes-256-gcm"
                            "aead_chacha20_poly1305" -> "chacha20-ietf-poly1305"
                            else -> return listOf()
                        }
                        val ssPassword = it["password"]?.toString() ?: ""
                        return listOf(TrojanGoBean().apply {
                            serverAddress = bean.serverAddress
                            serverPort = bean.serverPort
                            password = bean.password
                            sni = bean.sni
                            allowInsecure = bean.allowInsecure
                            encryption = "ss;$ssMethod:$ssPassword"
                        })
                    }
                }
            }
            return listOf(bean)
        }
        "ssr" -> {
            return listOf(ShadowsocksRBean().apply {
                serverAddress = proxy["server"]?.toString() ?: return listOf()
                serverPort = proxy["port"]?.toString()?.toUIntOrNull() ?: return listOf()
                method = when (val cipher = (proxy["cipher"] as? String)?.lowercase()) {
                    "dummy" -> "none"
                    in supportedShadowsocksRMethod -> cipher
                    else -> return listOf()
                }
                password = proxy["password"]?.toString()
                obfs = when (val it = proxy["obfs"] as? String) {
                    "tls1.2_ticket_fastauth" -> "tls1.2_ticket_auth"
                    in supportedShadowsocksRObfs -> it
                    else -> return listOf()
                }
                obfsParam = proxy["obfs-param"]?.toString()
                protocol = when (val it = proxy["protocol"] as? String) {
                    in supportedShadowsocksRProtocol -> it
                    else -> return listOf()
                }
                protocolParam = proxy["protocol-param"]?.toString()
                name = proxy["name"]?.toString()
            })
        }
        "ssh" -> {
            return listOf(SSHBean().apply {
                serverAddress = proxy["server"]?.toString() ?: return listOf()
                serverPort = proxy["port"]?.toString()?.toUIntOrNull() ?: return listOf()
                username = proxy["username"]?.toString()
                proxy["password"]?.toString()?.also {
                    password = it
                    authType = SSHBean.AUTH_TYPE_PASSWORD
                }
                proxy["private-key"]?.toString()?.also {
                    privateKey = it
                    authType = SSHBean.AUTH_TYPE_PRIVATE_KEY
                }
                privateKeyPassphrase = proxy["private-key-passphrase"]?.toString()
                publicKey = (proxy["host-key"] as? List<Any>)?.joinToString("\n")
                name = proxy["name"]?.toString()
            })
        }
        "hysteria" -> {
            return listOf(HysteriaBean().apply {
                serverAddress = proxy["server"]?.toString() ?: return listOf()
                serverPorts = (proxy["ports"]?.toString()?.takeIf { it.isValidHysteriaPort() }
                    ?: proxy["port"]?.toString()?.toUIntOrNull()?.toString()) ?: return listOf()
                (proxy["protocol"] as? String ?: proxy["obfs-protocol"] as? String)?.also {
                    protocol = when (it) {
                        "faketcp" -> HysteriaBean.PROTOCOL_FAKETCP
                        "wechat-video" -> HysteriaBean.PROTOCOL_WECHAT_VIDEO
                        "udp", "" -> HysteriaBean.PROTOCOL_UDP
                        else -> return listOf()
                    }
                }
                proxy["auth-str"]?.toString()?.takeIf { it.isNotEmpty() }?.also {
                    authPayloadType = HysteriaBean.TYPE_STRING
                    authPayload = it
                }
                proxy["auth"]?.toString()?.takeIf { it.isNotEmpty() }?.also {
                    authPayloadType = HysteriaBean.TYPE_BASE64
                    authPayload = it
                }
                sni = proxy["sni"]?.toString()
                alpn = (proxy["alpn"] as? List<Any>)?.get(0)?.toString()
                allowInsecure = proxy["skip-cert-verify"] as? Boolean == true
                obfuscation = proxy["obfs"]?.toString()?.takeIf { it.isNotEmpty() }
                hopInterval = proxy["hop-interval"]?.toString()?.toLongOrNull()?.takeIf { it > 0 }
                name = proxy["name"]?.toString()
            })
        }
        "hysteria2" -> {
            return listOf(Hysteria2Bean().apply {
                serverAddress = proxy["server"]?.toString() ?: return listOf()
                serverPorts = (proxy["ports"]?.toString()?.takeIf { it.isValidHysteriaPort() }
                    ?: proxy["port"]?.toString()?.toUIntOrNull()?.toString()) ?: return listOf()
                auth = proxy["password"]?.toString()
                // uploadMbps = (proxy["up"]?.toString())?.toMegaBitsPerSecond()
                // downloadMbps = (proxy["down"]?.toString())?.toMegaBitsPerSecond()
                sni = proxy["sni"]?.toString()
                // alpn = (proxy["alpn"] as? List<Any>)?.joinToString("\n")
                allowInsecure = proxy["skip-cert-verify"] as? Boolean == true
                (proxy["obfs"] as? String)?.also {
                    when (it) {
                        "" -> {}
                        "salamander" -> {
                            obfs = proxy["obfs-password"]?.toString()
                        }
                        else -> return listOf()
                    }
                }
                hopInterval = proxy["hop-interval"]?.toString()?.toLongOrNull()?.takeIf { it > 0 }
                name = proxy["name"]?.toString()
            })
        }
        "tuic" -> {
            if (proxy["token"] != null) {
                return listOf(TuicBean().apply {
                    serverAddress = proxy["ip"]?.toString() ?: proxy["server"]?.toString() ?: return listOf()
                    serverPort = proxy["port"]?.toString()?.toUIntOrNull() ?: return listOf()
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
                    sni = proxy["sni"]?.toString()
                        ?: (if (proxy["ip"]?.toString() != null) proxy["server"]?.toString() else null)
                    // https://github.com/MetaCubeX/mihomo/blob/d5243adf8911563677d3bd190b82623c93e554b7/adapter/outbound/tuic.go#L174-L178
                    alpn = if (!proxy.containsKey("alpn")) "h3" else (proxy["alpn"] as? List<Any>)?.joinToString("\n")
                    name = proxy["name"]?.toString()
                })
            } else {
                return listOf(Tuic5Bean().apply {
                    serverAddress = proxy["ip"]?.toString() ?: proxy["server"]?.toString() ?: return listOf()
                    serverPort = proxy["port"]?.toString()?.toUIntOrNull() ?: return listOf()
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
                    sni = proxy["sni"]?.toString()
                        ?: (if (proxy["ip"]?.toString() != null) proxy["server"]?.toString() else null)
                    // https://github.com/MetaCubeX/mihomo/blob/d5243adf8911563677d3bd190b82623c93e554b7/adapter/outbound/tuic.go#L174-L178
                    alpn = if (!proxy.containsKey("alpn")) "h3" else (proxy["alpn"] as? List<Any>)?.joinToString("\n")
                    name = proxy["name"]?.toString()
                })
            }
        }
        "mieru" -> {
            return listOf(MieruBean().apply {
                serverAddress = proxy["server"]?.toString() ?: return listOf()
                // Why yet another protocol containing port-range? Let us use the first port only for now.
                serverPort = (proxy["port"]?.toString()?.toUIntOrNull()
                    ?: (proxy["port-range"]?.toString())?.substringBefore("-")?.toIntOrNull())
                    ?: return listOf()
                username = proxy["username"]?.toString()
                password = proxy["password"]?.toString()
                protocol = MieruBean.PROTOCOL_TCP
                proxy["transport"]?.toString()?.also {
                    protocol = when (it) {
                        "TCP", "" -> MieruBean.PROTOCOL_TCP
                        "UDP" -> MieruBean.PROTOCOL_UDP // not implemented as of mihomo v1.19.0
                        else -> return listOf()
                    }
                }
                proxy["multiplexing"]?.toString()?.also {
                    multiplexingLevel = when (it) {
                        "MULTIPLEXING_OFF" -> MieruBean.MULTIPLEXING_OFF
                        "MULTIPLEXING_LOW" -> MieruBean.MULTIPLEXING_LOW
                        "MULTIPLEXING_MIDDLE" -> MieruBean.MULTIPLEXING_MIDDLE
                        "MULTIPLEXING_HIGH" -> MieruBean.MULTIPLEXING_HIGH
                        else -> MieruBean.MULTIPLEXING_LOW
                    }
                }
                name = proxy["name"]?.toString()
            })
        }
        "anytls" -> {
            return listOf(AnyTLSBean().apply {
                serverAddress = proxy["server"]?.toString() ?: return listOf()
                serverPort = proxy["port"]?.toString()?.toUIntOrNull() ?: return listOf()
                password = proxy["password"]?.toString()
                security = "tls"
                sni = proxy["sni"]?.toString()
                alpn = (proxy["alpn"] as? List<Any>)?.joinToString("\n")
                allowInsecure = proxy["skip-cert-verify"] as? Boolean == true
                name = proxy["name"]?.toString()
            })
        }
        "wireguard" -> {
            (proxy["amnezia-wg-option"] as? Map<String, Any?>)?.also {
                // unsupported
                return listOf()
            }
            val beanList = mutableListOf<WireGuardBean>()
            val bean = WireGuardBean().apply {
                serverAddress = proxy["server"]?.toString()
                serverPort = proxy["port"]?.toString()?.toUIntOrNull()
                privateKey = proxy["private-key"] as? String
                peerPublicKey = proxy["public-key"] as? String
                peerPreSharedKey = proxy["pre-shared-key"] as? String
                    ?: proxy["preshared-key"] as? String // "preshared-key" from Clash Premium
                mtu = (proxy["mtu"]?.toString()?.toUIntOrNull())?.takeIf { it > 0 } ?: 1408
                localAddress = listOfNotNull(proxy["ip"] as? String, proxy["ipv6"] as? String).joinToString("\n")
                keepaliveInterval = proxy["persistent-keepalive"]?.toString()?.toUIntOrNull()?.takeIf { it > 0 }
                name = proxy["name"]?.toString()
                (proxy["reserved"] as? List<Map<String, Any>>)?.also {
                    if (it.size == 3) {
                        reserved = listOf(
                            it[0].toString(),
                            it[1].toString(),
                            it[2].toString()
                        ).joinToString(",")
                    }
                } ?: {
                    Base64.decode(proxy["reserved"]?.toString())?.also {
                        if (it.size == 3) {
                            reserved = listOf(
                                it[0].toUByte().toInt().toString(),
                                it[1].toUByte().toInt().toString(),
                                it[2].toUByte().toInt().toString()
                            ).joinToString(",")
                        }
                    }
                }
            }
            if (proxy["server"] != null && proxy["port"] != null) {
                beanList.add(bean)
            }
            (proxy["peers"] as? List<Map<String, Any>>)?.forEach { peer ->
                if (peer["server"] != null && peer["port"] != null) {
                    beanList.add(bean.applyDefaultValues().clone().apply {
                        serverAddress = peer["server"]?.toString()
                        serverPort = peer["port"]?.toString()?.toUIntOrNull()
                        peerPublicKey = peer["public-key"] as? String
                        peerPreSharedKey = peer["pre-shared-key"] as? String
                        (peer["reserved"] as? List<Map<String, Any>>)?.also {
                            if (it.size == 3) {
                                reserved = listOf(
                                    it[0].toString(),
                                    it[1].toString(),
                                    it[2].toString()
                                ).joinToString(",")
                            }
                        } ?: {
                            Base64.decode(peer["reserved"]?.toString())?.also {
                                if (it.size == 3) {
                                    reserved = listOf(
                                        it[0].toUByte().toInt().toString(),
                                        it[1].toUByte().toInt().toString(),
                                        it[2].toUByte().toInt().toString()
                                    ).joinToString(",")
                                }
                            }
                        }
                    })
                }
            }
            return beanList
        }
        else -> return listOf()
    }
}