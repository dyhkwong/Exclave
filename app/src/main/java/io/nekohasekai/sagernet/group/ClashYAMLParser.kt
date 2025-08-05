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
                serverAddress = proxy.getString("server") ?: return listOf()
                serverPort = proxy.getString("port")?.toUIntOrNull() ?: return listOf()
                username = proxy.getString("username")
                password = proxy.getString("password")
                if (proxy.getBoolean("tls") == true) {
                    security = "tls"
                    if (proxy.getBoolean("skip-cert-verify") == true) {
                        allowInsecure = true
                    }
                }
                name = proxy.getString("name")
            })
        }
        "http" -> {
            return listOf(HttpBean().apply {
                serverAddress = proxy.getString("server") ?: return listOf()
                serverPort = proxy.getString("port")?.toUIntOrNull() ?: return listOf()
                username = proxy.getString("username")
                password = proxy.getString("password")
                if (proxy.getBoolean("tls") == true) {
                    security = "tls"
                    sni = proxy.getString("sni")
                    if (proxy.getBoolean("skip-cert-verify") == true) {
                        allowInsecure = true
                    }
                }
                name = proxy.getString("name")
            })
        }
        "ss" -> {
            var pluginStr = ""
            if (proxy.contains("plugin")) {
                val opts = proxy.getAny("plugin-opts") as? Map<String, Any?>
                val pluginOpts = PluginOptions()
                fun put(clash: String, origin: String = clash) {
                    opts?.getString(clash)?.let {
                        pluginOpts[origin] = it
                    }
                }
                when (proxy.getString("plugin")) {
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
                serverAddress = proxy.getString("server") ?: return listOf()
                serverPort = proxy.getString("port")?.toUIntOrNull() ?: return listOf()
                password = proxy.getString("password")
                method = when (val cipher = proxy.getString("cipher")?.lowercase()) {
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
                name = proxy.getString("name")
            })
        }
        "vmess", "vless", "trojan" -> {
            val bean = when (proxy["type"] as String) {
                "vmess" -> VMessBean()
                "vless" -> VLESSBean()
                "trojan" -> TrojanBean()
                else -> error("impossible")
            }.apply {
                serverAddress = proxy.getString("server") ?: return listOf()
                serverPort = proxy.getString("port")?.toUIntOrNull() ?: return listOf()
                name = proxy.getString("name")
            }

            if (bean is TrojanBean) {
                when (val network = proxy.getString("network")) {
                    "ws", "grpc" -> bean.type = network
                    else -> bean.type = "tcp"
                }
            } else {
                when (val network = proxy.getString("network")) {
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
                bean.sni = proxy.getString("sni")
                bean.password = proxy.getString("password")
            } else {
                bean.security = if (proxy.getBoolean("tls") == true) "tls" else "none"
                if (bean.security == "tls") {
                    bean.sni = proxy.getString("servername")
                }
                proxy.getString("uuid")?.takeIf { it.isNotEmpty() }?.also {
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
                bean.alterId = proxy.getString("alterId")?.toUIntOrNull()
                bean.encryption = when (val cipher = proxy.getString("cipher")) {
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
                when (proxy.getString("packet-encoding")) {
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
                when (proxy.getString("packet-encoding")) {
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
                    (proxy.getString("flow"))?.takeIf { it.isNotEmpty() }?.also {
                        if (it.startsWith("xtls-rprx-vision")) {
                            bean.flow = "xtls-rprx-vision-udp443"
                            bean.packetEncoding = "xudp"
                        } else return listOf()
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
                        val ssMethod = when (val method = it.getString("method")?.lowercase()) {
                            "aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305" -> method
                            "aead_aes_128_gcm", "" -> "aes-128-gcm"
                            "aead_aes_256_gcm" -> "aes-256-gcm"
                            "aead_chacha20_poly1305" -> "chacha20-ietf-poly1305"
                            else -> return listOf()
                        }
                        val ssPassword = it.getString("password") ?: ""
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
                serverAddress = proxy.getString("server") ?: return listOf()
                serverPort = proxy.getString("port")?.toUIntOrNull() ?: return listOf()
                method = when (val cipher = proxy.getString("cipher")?.lowercase()) {
                    "dummy" -> "none"
                    in supportedShadowsocksRMethod -> cipher
                    else -> return listOf()
                }
                password = proxy.getString("password")
                obfs = when (val it = proxy.getString("obfs")) {
                    "tls1.2_ticket_fastauth" -> "tls1.2_ticket_auth"
                    in supportedShadowsocksRObfs -> it
                    else -> return listOf()
                }
                obfsParam = proxy.getString("obfs-param")
                protocol = when (val it = proxy.getString("protocol")) {
                    in supportedShadowsocksRProtocol -> it
                    else -> return listOf()
                }
                protocolParam = proxy.getString("protocol-param")
                name = proxy.getString("name")
            })
        }
        "ssh" -> {
            return listOf(SSHBean().apply {
                serverAddress = proxy.getString("server") ?: return listOf()
                serverPort = proxy.getString("port")?.toUIntOrNull() ?: return listOf()
                username = proxy.getString("username")
                proxy.getString("password")?.also {
                    password = it
                    authType = SSHBean.AUTH_TYPE_PASSWORD
                }
                proxy.getString("private-key")?.also {
                    privateKey = it
                    authType = SSHBean.AUTH_TYPE_PRIVATE_KEY
                }
                privateKeyPassphrase = proxy.getString("private-key-passphrase")
                publicKey = (proxy.getAny("host-key") as? List<Any>)?.joinToString("\n")
                name = proxy.getString("name")
            })
        }
        "hysteria" -> {
            return listOf(HysteriaBean().apply {
                serverAddress = proxy.getString("server") ?: return listOf()
                serverPorts = (proxy.getString("ports")?.takeIf { it.isValidHysteriaPort() }
                    ?: proxy.getString("port")?.toUIntOrNull()?.toString()) ?: return listOf()
                (proxy.getString("protocol") ?: proxy.getString("obfs-protocol"))?.also {
                    protocol = when (it) {
                        "faketcp" -> HysteriaBean.PROTOCOL_FAKETCP
                        "wechat-video" -> HysteriaBean.PROTOCOL_WECHAT_VIDEO
                        "udp", "" -> HysteriaBean.PROTOCOL_UDP
                        else -> return listOf()
                    }
                }
                proxy.getString("auth-str")?.takeIf { it.isNotEmpty() }?.also {
                    authPayloadType = HysteriaBean.TYPE_STRING
                    authPayload = it
                }
                proxy.getString("auth")?.takeIf { it.isNotEmpty() }?.also {
                    authPayloadType = HysteriaBean.TYPE_BASE64
                    authPayload = it
                }
                sni = proxy.getString("sni")
                alpn = (proxy.getAny("alpn") as? List<Any>)?.get(0)?.toString()
                allowInsecure = proxy.getBoolean("skip-cert-verify") == true
                obfuscation = proxy.getString("obfs")?.takeIf { it.isNotEmpty() }
                hopInterval = proxy.getString("hop-interval")?.toUIntOrNull()?.toLong()
                name = proxy.getString("name")
            })
        }
        "hysteria2" -> {
            return listOf(Hysteria2Bean().apply {
                serverAddress = proxy.getString("server") ?: return listOf()
                serverPorts = (proxy.getString("ports")?.takeIf { it.isValidHysteriaPort() }
                    ?: proxy.getString("port")?.toUIntOrNull()?.toString()) ?: return listOf()
                auth = proxy.getString("password")
                sni = proxy.getString("sni")
                // alpn = (proxy.getAny("alpn") as? List<Any>)?.joinToString("\n")
                allowInsecure = proxy.getBoolean("skip-cert-verify") == true
                (proxy.getString("obfs"))?.also {
                    when (it) {
                        "" -> {}
                        "salamander" -> {
                            obfs = proxy.getString("obfs-password")
                        }
                        else -> return listOf()
                    }
                }
                hopInterval = proxy.getString("hop-interval")?.toUIntOrNull()?.toLong()
                name = proxy.getString("name")
            })
        }
        "tuic" -> {
            if (proxy.getString("token") != null) {
                return listOf(TuicBean().apply {
                    serverAddress = proxy.getString("ip") ?: proxy.getString("server") ?: return listOf()
                    serverPort = proxy.getString("port")?.toUIntOrNull() ?: return listOf()
                    token = proxy.getString("token")
                    udpRelayMode = when (val mode = proxy.getString("udp-relay-mode")) {
                        in supportedTuicRelayMode -> mode
                        else -> "native"
                    }
                    congestionController = when (val controller = proxy.getString("congestion-controller")) {
                        in supportedTuicCongestionControl -> controller
                        else -> "cubic"
                    }
                    disableSNI = proxy.getBoolean("disable-sni") == true
                    reduceRTT = proxy.getBoolean("reduce-rtt") == true
                    // allowInsecure = proxy.getBoolean("skip-cert-verify") == true
                    sni = proxy.getString("sni")
                        ?: (if (proxy.getString("ip") != null) proxy.getString("server") else null)
                    // https://github.com/MetaCubeX/mihomo/blob/d5243adf8911563677d3bd190b82623c93e554b7/adapter/outbound/tuic.go#L174-L178
                    alpn = if (!proxy.contains("alpn")) "h3" else (proxy.getAny("alpn") as? List<Any>)?.joinToString("\n")
                    name = proxy.getString("name")
                })
            } else {
                return listOf(Tuic5Bean().apply {
                    serverAddress = proxy.getString("ip") ?: proxy.getString("server") ?: return listOf()
                    serverPort = proxy.getString("port")?.toUIntOrNull() ?: return listOf()
                    uuid = proxy.getString("uuid")
                    password = proxy.getString("password")
                    udpRelayMode = when (val mode = proxy.getString("udp-relay-mode")) {
                        in supportedTuic5RelayMode -> mode
                        else -> "native"
                    }
                    congestionControl = when (val controller = proxy.getString("congestion-controller")) {
                        in supportedTuic5CongestionControl -> controller
                        else -> "cubic"
                    }
                    disableSNI = proxy.getBoolean("disable-sni") == true
                    zeroRTTHandshake = proxy.getBoolean("reduce-rtt") == true
                    allowInsecure = proxy.getBoolean("skip-cert-verify") == true
                    sni = proxy.getString("sni")
                        ?: (if (proxy.getString("ip") != null) proxy.getString("server") else null)
                    // https://github.com/MetaCubeX/mihomo/blob/d5243adf8911563677d3bd190b82623c93e554b7/adapter/outbound/tuic.go#L174-L178
                    alpn = if (!proxy.contains("alpn")) "h3" else (proxy.getAny("alpn") as? List<Any>)?.joinToString("\n")
                    name = proxy.getString("name")
                })
            }
        }
        "mieru" -> {
            return listOf(MieruBean().apply {
                serverAddress = proxy.getString("server") ?: return listOf()
                // Why yet another protocol containing port-range? Let us use the first port only for now.
                serverPort = (proxy.getString("port")?.toUIntOrNull()
                    ?: (proxy.getString("port-range"))?.substringBefore("-")?.toIntOrNull())
                    ?: return listOf()
                username = proxy.getString("username")
                password = proxy.getString("password")
                protocol = MieruBean.PROTOCOL_TCP
                proxy.getString("transport")?.also {
                    protocol = when (it) {
                        "TCP", "" -> MieruBean.PROTOCOL_TCP
                        "UDP" -> MieruBean.PROTOCOL_UDP // not implemented as of mihomo v1.19.0
                        else -> return listOf()
                    }
                }
                proxy.getString("multiplexing")?.also {
                    multiplexingLevel = when (it) {
                        "MULTIPLEXING_OFF" -> MieruBean.MULTIPLEXING_OFF
                        "MULTIPLEXING_LOW" -> MieruBean.MULTIPLEXING_LOW
                        "MULTIPLEXING_MIDDLE" -> MieruBean.MULTIPLEXING_MIDDLE
                        "MULTIPLEXING_HIGH" -> MieruBean.MULTIPLEXING_HIGH
                        else -> MieruBean.MULTIPLEXING_LOW
                    }
                }
                name = proxy.getString("name")
            })
        }
        "anytls" -> {
            return listOf(AnyTLSBean().apply {
                serverAddress = proxy.getString("server") ?: return listOf()
                serverPort = proxy.getString("port")?.toUIntOrNull() ?: return listOf()
                password = proxy.getString("password")
                security = "tls"
                sni = proxy.getString("sni")
                alpn = (proxy.getAny("alpn") as? List<Any>)?.joinToString("\n")
                allowInsecure = proxy.getBoolean("skip-cert-verify") == true
                name = proxy.getString("name")
            })
        }
        "wireguard" -> {
            (proxy.getAny("amnezia-wg-option") as? Map<String, Any?>)?.also {
                // unsupported
                return listOf()
            }
            val beanList = mutableListOf<WireGuardBean>()
            val bean = WireGuardBean().apply {
                serverAddress = proxy.getString("server")
                serverPort = proxy.getString("port")?.toUIntOrNull()
                privateKey = proxy.getString("private-key")
                peerPublicKey = proxy.getString("public-key")
                peerPreSharedKey = proxy.getString("pre-shared-key")
                    ?: proxy.getString("preshared-key") // "preshared-key" from Clash Premium
                mtu = (proxy.getString("mtu")?.toUIntOrNull())?.takeIf { it > 0 } ?: 1408
                localAddress = listOfNotNull(proxy.getString("ip"), proxy.getString("ipv6")).joinToString("\n")
                keepaliveInterval = proxy.getString("persistent-keepalive")?.toUIntOrNull()?.takeIf { it > 0 }
                name = proxy.getString("name")
                (proxy.getAny("reserved") as? List<Map<String, Any>>)?.also {
                    if (it.size == 3) {
                        reserved = listOf(
                            it[0].toString(),
                            it[1].toString(),
                            it[2].toString()
                        ).joinToString(",")
                    }
                } ?: {
                    Base64.decode(proxy.getString("reserved"))?.also {
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
                        serverAddress = peer.getString("server")
                        serverPort = peer.getString("port")?.toUIntOrNull()
                        peerPublicKey = peer.getString("public-key")
                        peerPreSharedKey = peer.getString("pre-shared-key")
                        (peer.getAny("reserved") as? List<Map<String, Any>>)?.also {
                            if (it.size == 3) {
                                reserved = listOf(
                                    it[0].toString(),
                                    it[1].toString(),
                                    it[2].toString()
                                ).joinToString(",")
                            }
                        } ?: {
                            Base64.decode(peer.getString("reserved"))?.also {
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