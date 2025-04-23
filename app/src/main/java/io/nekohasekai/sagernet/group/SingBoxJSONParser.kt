package io.nekohasekai.sagernet.group

import cn.hutool.core.codec.Base64
import cn.hutool.core.lang.UUID
import cn.hutool.json.JSONObject
import io.nekohasekai.sagernet.fmt.AbstractBean
import io.nekohasekai.sagernet.fmt.anytls.AnyTLSBean
import io.nekohasekai.sagernet.fmt.http.HttpBean
import io.nekohasekai.sagernet.fmt.hysteria.HysteriaBean
import io.nekohasekai.sagernet.fmt.hysteria2.Hysteria2Bean
import io.nekohasekai.sagernet.fmt.shadowsocks.ShadowsocksBean
import io.nekohasekai.sagernet.fmt.shadowsocks.supportedShadowsocksMethod
import io.nekohasekai.sagernet.fmt.shadowsocksr.ShadowsocksRBean
import io.nekohasekai.sagernet.fmt.shadowsocksr.supportedShadowsocksRMethod
import io.nekohasekai.sagernet.fmt.shadowsocksr.supportedShadowsocksRObfs
import io.nekohasekai.sagernet.fmt.shadowsocksr.supportedShadowsocksRProtocol
import io.nekohasekai.sagernet.fmt.socks.SOCKSBean
import io.nekohasekai.sagernet.fmt.ssh.SSHBean
import io.nekohasekai.sagernet.fmt.trojan.TrojanBean
import io.nekohasekai.sagernet.fmt.tuic5.Tuic5Bean
import io.nekohasekai.sagernet.fmt.tuic5.supportedTuic5CongestionControl
import io.nekohasekai.sagernet.fmt.tuic5.supportedTuic5RelayMode
import io.nekohasekai.sagernet.fmt.v2ray.VLESSBean
import io.nekohasekai.sagernet.fmt.v2ray.VMessBean
import io.nekohasekai.sagernet.fmt.v2ray.supportedVmessMethod
import io.nekohasekai.sagernet.fmt.wireguard.WireGuardBean
import io.nekohasekai.sagernet.ktx.*
import kotlin.time.Duration
import kotlin.time.DurationUnit

@Suppress("UNCHECKED_CAST")
fun parseSingBoxOutbound(outbound: JSONObject): List<AbstractBean> {
    when (val type = outbound["type"]) {
        "shadowsocks", "trojan", "vmess", "vless", "socks", "http" -> {
            val v2rayBean = when (type) {
                "shadowsocks" -> ShadowsocksBean()
                "trojan" -> TrojanBean()
                "vmess" -> VMessBean()
                "vless" -> VLESSBean()
                "socks" -> SOCKSBean()
                "http" -> HttpBean()
                else -> return listOf()
            }.apply {
                outbound["tag"]?.toString()?.also {
                    name = it
                }
                outbound.getString("server")?.also {
                    serverAddress = it
                } ?: return listOf()
                outbound.getInteger("server_port")?.also {
                    serverPort = it
                } ?: return listOf()
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
                            else -> return listOf()
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
                            else -> return listOf()
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
                        if (it != "" && it != "/") {
                            // unsupported
                            return listOf()
                        }
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
                        if (it !in supportedShadowsocksMethod) return listOf()
                        v2rayBean.method = it
                    }
                    outbound.getString("password")?.also {
                        v2rayBean.password = it
                    }
                    outbound.getString("plugin")?.takeIf { it.isNotEmpty() }?.also { plugin ->
                        if (plugin != "obfs-local" && plugin != "v2ray-plugin") return listOf()
                        v2rayBean.plugin = plugin
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
                            UUID.fromString(it).toString()
                        } catch (_: Exception) {
                            uuid5(it)
                        }
                    }
                    outbound.getString("security")?.also {
                        if (it !in supportedVmessMethod) return listOf()
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
                            UUID.fromString(it).toString()
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
                            else -> return listOf()
                        }
                    }
                }
            }
            return listOf(v2rayBean)
        }
        "hysteria2" -> {
            val hysteria2Bean = Hysteria2Bean().apply {
                outbound["tag"]?.toString()?.also {
                    name = it
                }
                outbound.getString("server")?.also {
                    serverAddress = it
                } ?: return listOf()
                (outbound.getInteger("server_port")?.also {
                    serverPorts = it.toString()
                } ?: (outbound.getAny("server_ports") as? List<String>)?.also {
                    serverPorts = it.joinToString(",").replace(":", "-")
                } ?: (outbound.getAny("server_ports") as? String)?.also {
                    serverPorts = it.replace(":", "-")
                }) ?: return listOf()
                if (!serverPorts.isValidHysteriaPort()) {
                    return listOf()
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
                        return listOf()
                    }
                    if (tls.getObject("reality")?.getBoolean("enabled") == true) {
                        return listOf()
                    }
                    tls.getString("server_name")?.also {
                        sni = it
                    }
                    tls.getBoolean("insecure")?.also {
                        allowInsecure = it
                    }
                } ?: return listOf()
                outbound.getObject("obfs")?.also { obfuscation ->
                    obfuscation.getString("type")?.takeIf { it.isNotEmpty() }?.also { type ->
                        if (type != "salamander") return listOf()
                        obfuscation.getString("password")?.also {
                            obfs = it
                        }
                    }
                }
                /*outbound.getInt("up_mbps")?.also {
                    uploadMbps = it
                }
                outbound.getInt("down_mbps")?.also {
                    downloadMbps = it
                }*/
            }
            return listOf(hysteria2Bean)
        }
        "hysteria" -> {
            val hysteriaBean = HysteriaBean().apply {
                outbound["tag"]?.toString()?.also {
                    name = it
                }
                outbound.getString("server")?.also {
                    serverAddress = it
                } ?: return listOf()
                (outbound.getInteger("server_port")?.also {
                    serverPorts = it.toString()
                } ?: (outbound.getAny("server_ports") as? List<String>)?.also {
                    serverPorts = it.joinToString(",").replace(":", "-")
                } ?: (outbound.getAny("server_ports") as? String)?.also {
                    serverPorts = it.replace(":", "-")
                }) ?: return listOf()
                if (!serverPorts.isValidHysteriaPort()) {
                    return listOf()
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
                        return listOf()
                    }
                    if (tls.getObject("reality")?.getBoolean("enabled") == true) {
                        return listOf()
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
                } ?: return listOf()
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
            return listOf(hysteriaBean)
        }
        "tuic" -> {
            val tuic5Bean = Tuic5Bean().apply {
                outbound["tag"]?.toString()?.also {
                    name = it
                }
                outbound.getString("server")?.also {
                    serverAddress = it
                } ?: return listOf()
                outbound.getInteger("server_port")?.also {
                    serverPort = it
                } ?: return listOf()
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
                        return listOf()
                    }
                    if (tls.getObject("reality")?.getBoolean("enabled") == true) {
                        return listOf()
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
                } ?: return listOf()
            }
            return listOf(tuic5Bean)
        }
        "ssh" -> {
            val sshBean = SSHBean().apply {
                outbound["tag"]?.toString()?.also {
                    name = it
                }
                outbound.getString("server")?.also {
                    serverAddress = it
                } ?: return listOf()
                outbound.getInteger("server_port")?.also {
                    serverPort = it
                } ?: return listOf()
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
            return listOf(sshBean)
        }
        "ssr" -> {
            // removed in v1.6.0
            val ssrBean = ShadowsocksRBean().apply {
                outbound["tag"]?.toString()?.also {
                    name = it
                }
                outbound.getString("server")?.also {
                    serverAddress = it
                } ?: return listOf()
                outbound.getInteger("server_port")?.also {
                    serverPort = it
                } ?: return listOf()
                outbound.getString("method")?.also {
                    if (it !in supportedShadowsocksRMethod) return listOf()
                    method = it
                }
                outbound.getString("password")?.also {
                    password = it
                }
                outbound.getString("obfs")?.also {
                    obfs = when (it) {
                        "tls1.2_ticket_fastauth" -> "tls1.2_ticket_auth"
                        in supportedShadowsocksRObfs -> it
                        else -> return listOf()
                    }
                }
                outbound.getString("obfs_param")?.also {
                    obfsParam = it
                }
                outbound.getString("protocol")?.also {
                    if (it !in supportedShadowsocksRProtocol) return listOf()
                    protocol = it
                }
                outbound.getString("protocol_param")?.also {
                    protocolParam = it
                }
            }
            return listOf(ssrBean)
        }
        "anytls" -> {
            val anytlsBean = AnyTLSBean().apply {
                outbound["tag"]?.toString()?.also {
                    name = it
                }
                outbound.getString("server")?.also {
                    serverAddress = it
                } ?: return listOf()
                outbound.getInteger("server_port")?.also {
                    serverPort = it
                } ?: return listOf()
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
            return listOf(anytlsBean)
        }
        "wireguard" -> {
            if (outbound.contains("address")) {
                // wireguard endpoint format introduced in 1.11.0-alpha.19
                return listOf()
            }
            val beanList = mutableListOf<WireGuardBean>()
            val bean = WireGuardBean().apply {
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
                } ?: return listOf()
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
                    bean.serverAddress = it
                } ?: return listOf()
                outbound.getInteger("server_port")?.also {
                    bean.serverPort = it
                } ?: return listOf()
                beanList.add(bean)
            }
            outbound.getArray("peers")?.forEach { json ->
                val peer = json as? JSONObject
                beanList.add(bean.applyDefaultValues().clone().apply {
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
            return beanList
        }
        else -> return listOf()
    }
}

@Suppress("UNCHECKED_CAST")
fun parseSingBoxEndpoint(endpoint: JSONObject): List<AbstractBean> {
    when (endpoint["type"]) {
        "wireguard" -> {
            val beanList = mutableListOf<WireGuardBean>()
            if (endpoint.contains("local_address")) {
                // legacy wireguard outbound format
                return listOf()
            }
            val bean = WireGuardBean().apply {
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
                } ?: return listOf()
            }
            endpoint.getArray("peers")?.forEach { json ->
                val peer = json as? JSONObject
                beanList.add(bean.applyDefaultValues().clone().apply {
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
            return beanList
        }
        else -> return listOf()
    }
}