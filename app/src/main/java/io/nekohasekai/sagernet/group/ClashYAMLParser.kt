/******************************************************************************
 *                                                                            *
 * Copyright (C) 2024 by dyhkwong                                             *
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

fun parseClashProxies(proxies: List<Map<String, Any?>>): List<AbstractBean> {
    val beans = mutableListOf<AbstractBean>()
    proxies.forEach {
        beans.addAll(parseClashProxy(it))
    }
    return beans
}

@Suppress("UNCHECKED_CAST")
fun parseClashProxy(proxy: Map<String, Any?>): List<AbstractBean> {
    when (proxy["type"]) {
        "socks5" -> {
            return listOf(SOCKSBean().apply {
                serverAddress = proxy.getClashString("server") ?: return listOf()
                serverPort = proxy.getClashInt("port")?.takeIf { it > 0 } ?: return listOf()
                username = proxy.getClashString("username")
                password = proxy.getClashString("password")
                if (proxy.getBoolean("tls") == true) {
                    security = "tls"
                    if (proxy.getBoolean("skip-cert-verify") == true) {
                        allowInsecure = true
                    }
                }
                name = proxy.getClashString("name")
            })
        }
        "http" -> {
            return listOf(HttpBean().apply {
                serverAddress = proxy.getClashString("server") ?: return listOf()
                serverPort = proxy.getClashInt("port")?.takeIf { it > 0 } ?: return listOf()
                username = proxy.getClashString("username")
                password = proxy.getClashString("password")
                if (proxy.getBoolean("tls") == true) {
                    security = "tls"
                    sni = proxy.getClashString("sni")
                    if (proxy.getBoolean("skip-cert-verify") == true) {
                        allowInsecure = true
                    }
                }
                name = proxy.getClashString("name")
            })
        }
        "ss" -> {
            var pluginStr = ""
            if (proxy.contains("plugin")) {
                val opts = proxy.getAny("plugin-opts") as? Map<String, Any?>
                val pluginOpts = PluginOptions()
                fun put(clash: String, origin: String = clash) {
                    opts?.getClashString(clash)?.let {
                        pluginOpts[origin] = it
                    }
                }
                when (proxy.getClashString("plugin")) {
                    "obfs" -> {
                        pluginOpts.id = "obfs-local"
                        put("mode", "obfs")
                        put("host", "obfs-host")
                    }
                    "v2ray-plugin" -> {
                        pluginOpts.id = "v2ray-plugin"
                        put("mode")
                        if (opts?.getBoolean("tls") == true) {
                            pluginOpts["tls"] = null
                        }
                        put("host")
                        put("path")
                        if (opts?.getBoolean("mux") == true) {
                            pluginOpts["mux"] = "8"
                        }
                        if (opts?.getBoolean("v2ray-http-upgrade") == true) {
                            return listOf()
                        }
                    }
                    "", null -> {}
                    else -> return listOf()
                }
                pluginStr = pluginOpts.toString(false)
            }
            return listOf(ShadowsocksBean().apply {
                serverAddress = proxy.getClashString("server") ?: return listOf()
                serverPort = proxy.getClashInt("port")?.takeIf { it > 0 } ?: return listOf()
                password = proxy.getClashString("password")
                method = when (val cipher = proxy.getClashString("cipher")?.lowercase()) {
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
                name = proxy.getClashString("name")
            })
        }
        "vmess", "vless", "trojan" -> {
            val bean = when (proxy["type"] as String) {
                "vmess" -> VMessBean()
                "vless" -> VLESSBean()
                "trojan" -> TrojanBean()
                else -> error("impossible")
            }.apply {
                serverAddress = proxy.getClashString("server") ?: return listOf()
                serverPort = proxy.getClashInt("port")?.takeIf { it > 0 } ?: return listOf()
                name = proxy.getClashString("name")
            }

            if (bean is TrojanBean) {
                when (val network = proxy.getClashString("network")) {
                    "ws", "grpc" -> bean.type = network
                    else -> bean.type = "tcp"
                }
            } else {
                when (val network = proxy.getClashString("network")) {
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
                bean.sni = proxy.getClashString("sni")
                bean.password = proxy.getClashString("password")
            } else {
                bean.security = if (proxy.getBoolean("tls") == true) "tls" else "none"
                if (bean.security == "tls") {
                    bean.sni = proxy.getClashString("servername")
                }
                proxy.getClashString("uuid")?.also {
                    bean.uuid = try {
                        UUID.fromString(it).toString()
                    } catch (_: Exception) {
                        uuid5(it)
                    }
                }
            }
            if (bean.security == "tls") {
                bean.alpn = (proxy.getAny("alpn") as? List<Any>)?.joinToString("\n")
                bean.allowInsecure = proxy.getBoolean("skip-cert-verify") == true
            }

            if (bean is VMessBean) {
                bean.alterId = proxy.getClashInt("alterId") ?: return listOf()
                bean.encryption = when (val cipher = proxy.getClashString("cipher")) {
                    in supportedVmessMethod -> cipher
                    else -> return listOf()
                }
                bean.experimentalAuthenticatedLength = proxy.getBoolean("authenticated-length") == true
                var isPacket = false
                var isXUDP = false
                if (proxy.getBoolean("packet-addr") == true) {
                    isPacket = true
                    isXUDP = false
                }
                if (proxy.getBoolean("xudp") == true) {
                    isXUDP = true
                    isPacket = false
                }
                when (proxy.getClashString("packet-encoding")) {
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
                if (proxy.getBoolean("packet-addr") == true) {
                    isPacket = true
                    isXUDP = false
                }
                if (proxy.getBoolean("xudp") == true) {
                    isXUDP = true
                    isPacket = false
                }
                when (proxy.getClashString("packet-encoding")) {
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
                    (proxy.getClashString("flow"))?.takeIf { it.isNotEmpty() }?.also {
                        if (it.startsWith("xtls-rprx-vision")) {
                            bean.flow = "xtls-rprx-vision-udp443"
                            bean.packetEncoding = "xudp"
                        } else return listOf()
                    }
                }
                when (val encryption = proxy.getString("encryption")) {
                    "", "none", null -> bean.encryption = "none"
                    else -> {
                        val parts = encryption.split(".")
                        if (parts.size < 4 || parts[0] != "mlkem768x25519plus"
                            || !(parts[1] == "native" || parts[1] == "xorpub" || parts[1] == "random")
                            || !(parts[2] == "1rtt" || parts[2] == "0rtt")) {
                            error("unsupported vless encryption")
                        }
                        bean.encryption = encryption
                    }
                }
            }

            (proxy.getAny("reality-opts") as? Map<String, Any?>)?.also {
                for (realityOpt in it) {
                    bean.security = "reality"
                    when (realityOpt.key.lowercase()) {
                        "public-key" -> bean.realityPublicKey = realityOpt.value?.toString()
                        "short-id" -> bean.realityShortId = realityOpt.value?.toString()
                    }
                }
            }

            if (bean.type == "tcp" && bean.headerType != null && bean.headerType == "http") {
                (proxy.getAny("http-opts") as? Map<String, Any?>)?.also {
                    for (httpOpt in it) {
                        when (httpOpt.key.lowercase()) {
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
                (proxy.getAny("ws-opts") as? Map<String, Any?>)?.also { wsOpts ->
                    for (wsOpt in wsOpts) {
                        when (wsOpt.key.lowercase()) {
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
                                bean.maxEarlyData = wsOpt.value?.toString()?.toInt()
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
                (proxy.getAny("h2-opts") as? Map<String, Any?>)?.also {
                    for (h2Opt in it) {
                        when (h2Opt.key.lowercase()) {
                            "host" -> bean.host = (h2Opt.value as? List<Any>)?.joinToString("\n")
                            "path" -> bean.path = h2Opt.value?.toString()
                        }
                    }
                }
            }
            if (bean.type == "grpc") {
                (proxy.getAny("grpc-opts") as? Map<String, Any?>)?.also {
                    for (grpcOpt in it) {
                        when (grpcOpt.key.lowercase()) {
                            "grpc-service-name" -> bean.grpcServiceName = grpcOpt.value?.toString()
                        }
                    }
                }
            }

            if (bean is TrojanBean) {
                (proxy.getAny("ss-opts") as? Map<String, Any?>)?.also {
                    if (it.getBoolean("enabled") == true) {
                        if (bean.security != "tls") {
                            // unsupported
                            return listOf()
                        }
                        val ssMethod = when (val method = it.getClashString("method")?.lowercase()) {
                            "aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305" -> method
                            "aead_aes_128_gcm", "" -> "aes-128-gcm"
                            "aead_aes_256_gcm" -> "aes-256-gcm"
                            "aead_chacha20_poly1305" -> "chacha20-ietf-poly1305"
                            else -> return listOf()
                        }
                        val ssPassword = it.getClashString("password") ?: ""
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
                serverAddress = proxy.getClashString("server") ?: return listOf()
                serverPort = proxy.getClashInt("port")?.takeIf { it > 0 } ?: return listOf()
                method = when (val cipher = proxy.getClashString("cipher")?.lowercase()) {
                    "dummy" -> "none"
                    in supportedShadowsocksRMethod -> cipher
                    else -> return listOf()
                }
                password = proxy.getClashString("password")
                obfs = when (val it = proxy.getClashString("obfs")) {
                    "tls1.2_ticket_fastauth" -> "tls1.2_ticket_auth"
                    in supportedShadowsocksRObfs -> it
                    else -> return listOf()
                }
                obfsParam = proxy.getClashString("obfs-param")
                protocol = when (val it = proxy.getClashString("protocol")) {
                    in supportedShadowsocksRProtocol -> it
                    else -> return listOf()
                }
                protocolParam = proxy.getClashString("protocol-param")
                name = proxy.getClashString("name")
            })
        }
        "ssh" -> {
            return listOf(SSHBean().apply {
                serverAddress = proxy.getClashString("server") ?: return listOf()
                serverPort = proxy.getClashInt("port")?.takeIf { it > 0 } ?: return listOf()
                username = proxy.getClashString("username")
                proxy.getClashString("password")?.also {
                    password = it
                    authType = SSHBean.AUTH_TYPE_PASSWORD
                }
                proxy.getClashString("private-key")?.also {
                    privateKey = it
                    authType = SSHBean.AUTH_TYPE_PRIVATE_KEY
                }
                privateKeyPassphrase = proxy.getClashString("private-key-passphrase")
                publicKey = (proxy.getAny("host-key") as? List<Any>)?.joinToString("\n")
                name = proxy.getClashString("name")
            })
        }
        "hysteria" -> {
            return listOf(HysteriaBean().apply {
                serverAddress = proxy.getClashString("server") ?: return listOf()
                serverPorts = (proxy.getClashString("ports")?.takeIf { it.isValidHysteriaPort() }
                    ?: proxy.getClashInt("port")?.takeIf { it > 0 }?.toString()) ?: return listOf()
                (proxy.getClashString("protocol") ?: proxy.getClashString("obfs-protocol"))?.also {
                    protocol = when (it) {
                        "faketcp" -> HysteriaBean.PROTOCOL_FAKETCP
                        "wechat-video" -> HysteriaBean.PROTOCOL_WECHAT_VIDEO
                        "udp", "" -> HysteriaBean.PROTOCOL_UDP
                        else -> return listOf()
                    }
                }
                proxy.getClashString("auth-str")?.takeIf { it.isNotEmpty() }?.also {
                    authPayloadType = HysteriaBean.TYPE_STRING
                    authPayload = it
                }
                proxy.getClashString("auth")?.takeIf { it.isNotEmpty() }?.also {
                    authPayloadType = HysteriaBean.TYPE_BASE64
                    authPayload = it
                }
                sni = proxy.getClashString("sni")
                alpn = (proxy.getAny("alpn") as? List<Any>)?.get(0)?.toString()
                allowInsecure = proxy.getBoolean("skip-cert-verify") == true
                obfuscation = proxy.getClashString("obfs")?.takeIf { it.isNotEmpty() }
                hopInterval = proxy.getClashString("hop-interval")?.toUIntOrNull()?.toLong()
                name = proxy.getClashString("name")
            })
        }
        "hysteria2" -> {
            return listOf(Hysteria2Bean().apply {
                serverAddress = proxy.getClashString("server") ?: return listOf()
                serverPorts = (proxy.getClashString("ports")?.takeIf { it.isValidHysteriaPort() }
                    ?: proxy.getClashString("port")?.toUIntOrNull()?.toString()) ?: return listOf()
                auth = proxy.getClashString("password")
                sni = proxy.getClashString("sni")
                // alpn = (proxy.getAny("alpn") as? List<Any>)?.joinToString("\n")
                allowInsecure = proxy.getBoolean("skip-cert-verify") == true
                (proxy.getClashString("obfs"))?.also {
                    when (it) {
                        "" -> {}
                        "salamander" -> {
                            obfs = proxy.getClashString("obfs-password")
                        }
                        else -> return listOf()
                    }
                }
                hopInterval = proxy.getClashString("hop-interval")?.toUIntOrNull()?.toLong()
                name = proxy.getClashString("name")
            })
        }
        "tuic" -> {
            if (proxy.getClashString("token") != null) {
                return listOf(TuicBean().apply {
                    serverAddress = proxy.getClashString("ip") ?: proxy.getClashString("server") ?: return listOf()
                    serverPort = proxy.getClashInt("port")?.takeIf { it > 0 } ?: return listOf()
                    token = proxy.getClashString("token")
                    udpRelayMode = when (val mode = proxy.getClashString("udp-relay-mode")) {
                        in supportedTuicRelayMode -> mode
                        else -> "native"
                    }
                    congestionController = when (val controller = proxy.getClashString("congestion-controller")) {
                        in supportedTuicCongestionControl -> controller
                        else -> "cubic"
                    }
                    disableSNI = proxy.getBoolean("disable-sni") == true
                    reduceRTT = proxy.getBoolean("reduce-rtt") == true
                    // allowInsecure = proxy.getBoolean("skip-cert-verify") == true
                    sni = proxy.getClashString("sni")
                        ?: (if (proxy.getClashString("ip") != null) proxy.getClashString("server") else null)
                    // https://github.com/MetaCubeX/mihomo/blob/d5243adf8911563677d3bd190b82623c93e554b7/adapter/outbound/tuic.go#L174-L178
                    alpn = if (!proxy.contains("alpn")) "h3" else (proxy.getAny("alpn") as? List<Any>)?.joinToString("\n")
                    name = proxy.getClashString("name")
                })
            } else {
                return listOf(Tuic5Bean().apply {
                    serverAddress = proxy.getClashString("ip") ?: proxy.getClashString("server") ?: return listOf()
                    serverPort = proxy.getClashInt("port")?.takeIf { it > 0 } ?: return listOf()
                    uuid = proxy.getClashString("uuid")
                    password = proxy.getClashString("password")
                    udpRelayMode = when (val mode = proxy.getClashString("udp-relay-mode")) {
                        in supportedTuic5RelayMode -> mode
                        else -> "native"
                    }
                    congestionControl = when (val controller = proxy.getClashString("congestion-controller")) {
                        in supportedTuic5CongestionControl -> controller
                        else -> "cubic"
                    }
                    disableSNI = proxy.getBoolean("disable-sni") == true
                    zeroRTTHandshake = proxy.getBoolean("reduce-rtt") == true
                    allowInsecure = proxy.getBoolean("skip-cert-verify") == true
                    sni = proxy.getClashString("sni")
                        ?: (if (proxy.getClashString("ip") != null) proxy.getClashString("server") else null)
                    // https://github.com/MetaCubeX/mihomo/blob/d5243adf8911563677d3bd190b82623c93e554b7/adapter/outbound/tuic.go#L174-L178
                    alpn = if (!proxy.contains("alpn")) "h3" else (proxy.getAny("alpn") as? List<Any>)?.joinToString("\n")
                    name = proxy.getClashString("name")
                })
            }
        }
        "mieru" -> {
            return listOf(MieruBean().apply {
                serverAddress = proxy.getClashString("server") ?: return listOf()
                // Why yet another protocol containing port-range? Let us use the first port only for now.
                serverPort = (proxy.getClashInt("port")?.takeIf { it > 0 }
                    ?: (proxy.getClashString("port-range"))?.substringBefore("-")?.toIntOrNull())
                    ?: return listOf()
                username = proxy.getClashString("username")
                password = proxy.getClashString("password")
                protocol = MieruBean.PROTOCOL_TCP
                proxy.getClashString("transport")?.also {
                    protocol = when (it) {
                        "TCP", "" -> MieruBean.PROTOCOL_TCP
                        "UDP" -> MieruBean.PROTOCOL_UDP // not implemented as of mihomo v1.19.0
                        else -> return listOf()
                    }
                }
                proxy.getClashString("multiplexing")?.also {
                    multiplexingLevel = when (it) {
                        "MULTIPLEXING_OFF" -> MieruBean.MULTIPLEXING_OFF
                        "MULTIPLEXING_LOW" -> MieruBean.MULTIPLEXING_LOW
                        "MULTIPLEXING_MIDDLE" -> MieruBean.MULTIPLEXING_MIDDLE
                        "MULTIPLEXING_HIGH" -> MieruBean.MULTIPLEXING_HIGH
                        else -> MieruBean.MULTIPLEXING_LOW
                    }
                }
                name = proxy.getClashString("name")
            })
        }
        "anytls" -> {
            return listOf(AnyTLSBean().apply {
                serverAddress = proxy.getClashString("server") ?: return listOf()
                serverPort = proxy.getClashInt("port")?.takeIf { it > 0 } ?: return listOf()
                password = proxy.getClashString("password")
                security = "tls"
                sni = proxy.getClashString("sni")
                alpn = (proxy.getAny("alpn") as? List<Any>)?.joinToString("\n")
                allowInsecure = proxy.getBoolean("skip-cert-verify") == true
                name = proxy.getClashString("name")
            })
        }
        "wireguard" -> {
            (proxy.getAny("amnezia-wg-option") as? Map<String, Any?>)?.also {
                // unsupported
                return listOf()
            }
            val beanList = mutableListOf<WireGuardBean>()
            val bean = WireGuardBean().apply {
                serverAddress = proxy.getClashString("server")
                serverPort = proxy.getClashInt("port")
                privateKey = proxy.getClashString("private-key")
                peerPublicKey = proxy.getClashString("public-key")
                peerPreSharedKey = proxy.getClashString("pre-shared-key")
                    ?: proxy.getClashString("preshared-key") // "preshared-key" from Clash Premium
                mtu = (proxy.getClashInt("mtu"))?.takeIf { it > 0 } ?: 1408
                localAddress = listOfNotNull(proxy.getClashString("ip"), proxy.getClashString("ipv6")).joinToString("\n")
                keepaliveInterval = proxy.getClashInt("persistent-keepalive")
                name = proxy.getClashString("name")
                (proxy.getAny("reserved") as? List<Map<String, Any>>)?.also {
                    if (it.size == 3) {
                        reserved = listOf(
                            it[0].toString(),
                            it[1].toString(),
                            it[2].toString()
                        ).joinToString(",")
                    }
                } ?: {
                    Base64.decode(proxy.getClashString("reserved"))?.also {
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
            if (proxy.contains("server") && proxy.contains("port")) {
                beanList.add(bean)
            }
            (proxy.getAny("peers") as? List<Map<String, Any>>)?.forEach { peer ->
                if (peer.contains("server") && peer.contains("port")) {
                    beanList.add(bean.applyDefaultValues().clone().apply {
                        serverAddress = peer.getClashString("server")
                        serverPort = peer.getClashInt("port")
                        peerPublicKey = peer.getClashString("public-key")
                        peerPreSharedKey = peer.getClashString("pre-shared-key")
                        (peer.getAny("reserved") as? List<Map<String, Any>>)?.also {
                            if (it.size == 3) {
                                reserved = listOf(
                                    it[0].toString(),
                                    it[1].toString(),
                                    it[2].toString()
                                ).joinToString(",")
                            }
                        } ?: {
                            Base64.decode(peer.getClashString("reserved"))?.also {
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

private fun Map<String, Any?>.getClashString(key: String): String? {
    if (this.contains(key)) {
        return when (val value = this[key]) {
            is String -> value
            is Int -> value.toString()
            // is Float -> value.toString()
            else -> null
        }
    }
    for (it in this) {
        if (it.key.lowercase() == key.lowercase()) {
            return when (val value = it.value) {
                is String -> value
                is Int -> value.toString()
                // is Float -> value.toString()
                else -> null
            }
        }
    }
    return null
}

private fun Map<String, Any?>.getClashInt(key: String): Int? {
    if (this.contains(key)) {
        return when (val value = this[key]) {
            is Int -> return value
            is String -> return value.convertClashStringToInt()
            // is Float -> return value.toString().convertClashStringToInt()
            else -> null
        }
    }
    for (it in this) {
        if (it.key.lowercase() == key.lowercase()) {
            return when (val value = it.value) {
                is Int -> value
                is String -> value.convertClashStringToInt()
                // is Float -> return value.toString().convertClashStringToInt()
                else -> null
            }
        }
    }
    return null
}

private fun String.convertClashStringToInt(): Int? {
    if (this.contains(":")) return null
    if (!this.startsWith("_") && this.replace("_", "").toFloatOrNull() != null) {
        return this.replace("_", "").toFloat().toInt()
    }
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