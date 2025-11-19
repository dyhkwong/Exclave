/******************************************************************************
 *                                                                            *
 * Copyright (C) 2024  dyhkwong                                               *
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
 * along with this program. If not, see <https://www.gnu.org/licenses/>.      *
 *                                                                            *
 ******************************************************************************/

package io.nekohasekai.sagernet.group

import com.github.shadowsocks.plugin.PluginOptions
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
import org.json.JSONObject
import kotlin.io.encoding.Base64
import kotlin.time.Duration
import kotlin.time.DurationUnit

@Suppress("UNCHECKED_CAST")
fun parseSingBoxOutbound(outbound: JSONObject): List<AbstractBean> {
    when (val type = outbound.optStringOrNull("type")) {
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
                outbound.optStringOrNull("tag")?.also {
                    name = it
                }
                outbound.optStr("server")?.also {
                    serverAddress = it
                } ?: return listOf()
                outbound.optInteger("server_port")?.also {
                    serverPort = it
                } ?: return listOf()
            }
            when (type) {
                "trojan", "vmess", "vless" -> {
                    outbound.optObject("transport")?.takeIf { it.length() > 0 }?.also { transport ->
                        when (transport.optStr("type")) {
                            "ws" -> {
                                v2rayBean.type = "ws"
                                transport.optStr("path")?.also {
                                    v2rayBean.path = it
                                }
                                transport.optObject("headers")?.also { headers ->
                                    headers.optArray("host")?.filterIsInstance<String>()?.get(0)?.also {
                                        v2rayBean.host = it
                                    } ?: headers.optStr("host")?.also {
                                        v2rayBean.host = it
                                    }
                                }
                                transport.optInteger("max_early_data")?.also {
                                    v2rayBean.maxEarlyData = it
                                }
                                transport.optStr("early_data_header_name")?.also {
                                    v2rayBean.earlyDataHeaderName = it
                                }
                            }
                            "http" -> {
                                v2rayBean.type = "tcp"
                                v2rayBean.headerType = "http"
                                // Difference from v2ray-core
                                // TLS is not enforced. If TLS is not configured, plain HTTP 1.1 is used.
                                outbound.optObject("tls")?.also {
                                    if (it.optBool("enabled") == true) {
                                        v2rayBean.type = "http"
                                        v2rayBean.headerType = null
                                    }
                                }
                                transport.optStr("path")?.also {
                                    v2rayBean.path = it
                                }
                                transport.optArray("host")?.filterIsInstance<String>()?.also {
                                    v2rayBean.host = it.joinToString("\n")
                                } ?: transport.optStr("host")?.also {
                                    v2rayBean.host = it
                                }
                            }
                            "quic" -> {
                                v2rayBean.type = "quic"
                            }
                            "grpc" -> {
                                v2rayBean.type = "grpc"
                                transport.optStr("service_name")?.also {
                                    v2rayBean.grpcServiceName = it
                                }
                            }
                            "httpupgrade" -> {
                                v2rayBean.type = "httpupgrade"
                                transport.optStr("host")?.also {
                                    v2rayBean.host = it
                                }
                                transport.optStr("path")?.also {
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
                    outbound.optObject("tls")?.also { tls ->
                        (tls.optBool("enabled"))?.also { enabled ->
                            if (enabled) {
                                v2rayBean.security = "tls"
                                tls.optStr("server_name")?.also {
                                    v2rayBean.sni = it
                                }
                                tls.optBool("insecure")?.also {
                                    v2rayBean.allowInsecure = it
                                }
                                tls.optArray("alpn")?.filterIsInstance<String>()?.also {
                                    v2rayBean.alpn = it.joinToString("\n")
                                } ?: tls.optStr("alpn")?.also {
                                    v2rayBean.alpn = it
                                }
                                if (v2rayBean.alpn == null && v2rayBean.type == "quic") {
                                    // https://github.com/SagerNet/sing-box/pull/1934
                                    v2rayBean.alpn = "h3"
                                }
                                if (!tls.hasCaseInsensitive("certificate_path")) {
                                    var cert: String? = null
                                    tls.optArray("certificate")?.filterIsInstance<String>()?.also { certificate ->
                                        cert = certificate.joinToString("\n").takeIf {
                                            it.contains("-----BEGIN ") && it.contains("-----END ") && it.contains(" CERTIFICATE-----")
                                        }
                                    } ?: tls.optStr("certificate")?.also { certificate ->
                                        cert = certificate.takeIf {
                                            it.contains("-----BEGIN ") && it.contains("-----END ") && it.contains(" CERTIFICATE-----")
                                        }
                                    }
                                    if (cert != null) {
                                        v2rayBean.certificates = cert
                                    }
                                }
                                if (!tls.hasCaseInsensitive("client_certificate_path") && !tls.hasCaseInsensitive("client_key_path")) {
                                    var cert: String? = null
                                    tls.optArray("client_certificate")?.filterIsInstance<String>()?.also { clientCert ->
                                        cert = clientCert.joinToString("\n").takeIf {
                                            it.contains("-----BEGIN ") && it.contains("-----END ") && it.contains(" CERTIFICATE-----")
                                        }
                                    } ?: tls.optStr("client_certificate")?.also { clientCert ->
                                        cert = clientCert.takeIf {
                                            it.contains("-----BEGIN ") && it.contains("-----END ") && it.contains(" CERTIFICATE-----")
                                        }
                                    }
                                    var key: String? = null
                                    tls.optArray("client_key")?.filterIsInstance<String>()?.also { clientKey ->
                                        key = clientKey.joinToString("\n").takeIf {
                                            it.contains("-----BEGIN ") && it.contains("-----END ") && it.contains(" PRIVATE KEY-----")
                                        }
                                    } ?: tls.optStr("client_key")?.also { clientKey ->
                                        key = clientKey.takeIf {
                                            it.contains("-----BEGIN ") && it.contains("-----END ") && it.contains(" PRIVATE KEY-----")
                                        }
                                    }
                                    if (cert != null && key != null) {
                                        v2rayBean.mtlsCertificate = cert
                                        v2rayBean.mtlsCertificatePrivateKey = key
                                    }
                                }
                                tls.optArray("certificate_public_key_sha256")?.filterIsInstance<String>()?.also {
                                    v2rayBean.pinnedPeerCertificatePublicKeySha256 = it.joinToString("\n")
                                    v2rayBean.allowInsecure = true
                                } ?: tls.optStr("certificate_public_key_sha256")?.also {
                                    v2rayBean.pinnedPeerCertificatePublicKeySha256 = it
                                    v2rayBean.allowInsecure = true
                                }
                                tls.optObject("reality")?.also { reality ->
                                    reality.optBool("enabled")?.also { enabled ->
                                        if (enabled) {
                                            v2rayBean.security = "reality"
                                            reality.optStr("public_key")?.also {
                                                v2rayBean.realityPublicKey = it
                                            }
                                            reality.optStr("short_id")?.also {
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
                    outbound.optStr("version")?.also {
                        v2rayBean.protocol = when (it) {
                            "4" -> SOCKSBean.PROTOCOL_SOCKS4
                            "4a" -> SOCKSBean.PROTOCOL_SOCKS4A
                            "", "5" -> SOCKSBean.PROTOCOL_SOCKS5
                            else -> return listOf()
                        }
                    }
                    outbound.optStr("username")?.also {
                        v2rayBean.username = it
                    }
                    outbound.optStr("password")?.also {
                        v2rayBean.password = it
                    }
                }
                "http" -> {
                    v2rayBean as HttpBean
                    outbound.optStr("path")?.also {
                        if (it != "" && it != "/") {
                            // unsupported
                            return listOf()
                        }
                    }
                    outbound.optStr("username")?.also {
                        v2rayBean.username = it
                    }
                    outbound.optStr("password")?.also {
                        v2rayBean.password = it
                    }
                }
                "shadowsocks" -> {
                    v2rayBean as ShadowsocksBean
                    outbound.optStr("method")?.also {
                        if (it !in supportedShadowsocksMethod) return listOf()
                        v2rayBean.method = it
                    }
                    outbound.optStr("password")?.also {
                        v2rayBean.password = it
                    }
                    outbound.optStr("plugin")?.takeIf { it.isNotEmpty() }?.also { pluginId ->
                        if (pluginId != "obfs-local" && pluginId != "v2ray-plugin") return listOf()
                        v2rayBean.plugin = PluginOptions(pluginId, outbound.optStr("plugin_opts")).toString(trimId = false)
                    }
                }
                "trojan" -> {
                    v2rayBean as TrojanBean
                    outbound.optStr("password")?.also {
                        v2rayBean.password = it
                    }
                }
                "vmess" -> {
                    v2rayBean as VMessBean
                    outbound.optStr("uuid")?.also {
                        v2rayBean.uuid = uuidOrGenerate(it)
                    }
                    outbound.optStr("security")?.also {
                        if (it !in supportedVmessMethod) return listOf()
                        v2rayBean.encryption = it
                    }
                    outbound.optInteger("alter_id")?.also {
                        v2rayBean.alterId = it
                    }
                    outbound.optBool("global_padding")?.also {
                        v2rayBean.experimentalAuthenticatedLength = it
                    }
                    v2rayBean.packetEncoding = when (outbound.optStr("packet_encoding")) {
                        "packetaddr" -> "packet"
                        "xudp" -> "xudp"
                        else -> "none"
                    }
                }
                "vless" -> {
                    v2rayBean as VLESSBean
                    outbound.optStr("uuid")?.also {
                        v2rayBean.uuid = uuidOrGenerate(it)
                    }
                    v2rayBean.packetEncoding = when (outbound.optStr("packet_encoding")) {
                        "packetaddr" -> "packet"
                        "xudp", null -> "xudp"
                        else -> "none"
                    }
                    outbound.optStr("flow")?.also {
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
                outbound.optStringOrNull("tag")?.also {
                    name = it
                }
                outbound.optStr("server")?.also {
                    serverAddress = it
                } ?: return listOf()
                (outbound.optInteger("server_port")?.also {
                    serverPorts = it.toString()
                } ?: outbound.optArray("server_ports")?.filterIsInstance<String>()?.also {
                    serverPorts = it.joinToString(",").replace(":", "-")
                } ?: outbound.optStr("server_ports")?.also {
                    serverPorts = it.replace(":", "-")
                }) ?: return listOf()
                if (!serverPorts.isValidHysteriaPort()) {
                    return listOf()
                }
                outbound.optStr("hop_interval")?.also { interval ->
                    try {
                        val duration = Duration.parse(interval)
                        hopInterval = duration.toLong(DurationUnit.SECONDS).takeIf { it > 0 }
                    } catch (_: Exception) {}
                }
                outbound.optStr("password")?.also {
                    auth = it
                }
                outbound.optObject("tls")?.also { tls ->
                    if (tls.optBool("enabled") != true) {
                        return listOf()
                    }
                    if (tls.optObject("reality")?.optBool("enabled") == true) {
                        return listOf()
                    }
                    tls.optStr("server_name")?.also {
                        sni = it
                    }
                    tls.optBool("insecure")?.also {
                        allowInsecure = it
                    }
                    if (!tls.hasCaseInsensitive("certificate_path")) {
                        var cert: String? = null
                        tls.optArray("certificate")?.filterIsInstance<String>()?.also { certificate ->
                            cert = certificate.joinToString("\n").takeIf {
                                it.contains("-----BEGIN ") && it.contains("-----END ") && it.contains(" CERTIFICATE-----")
                            }
                        } ?: tls.optStr("certificate")?.also { certificate ->
                            cert = certificate.takeIf {
                                it.contains("-----BEGIN ") && it.contains("-----END ") && it.contains(" CERTIFICATE-----")
                            }
                        }
                        if (cert != null) {
                            certificates = cert
                        }
                    }
                    if (!tls.hasCaseInsensitive("client_certificate_path") && !tls.hasCaseInsensitive("client_key_path")) {
                        var cert: String? = null
                        tls.optArray("client_certificate")?.filterIsInstance<String>()?.also { clientCert ->
                            cert = clientCert.joinToString("\n").takeIf {
                                it.contains("-----BEGIN ") && it.contains("-----END ") && it.contains(" CERTIFICATE-----")
                            }
                        } ?: tls.optStr("client_certificate")?.also { clientCert ->
                            cert = clientCert.takeIf {
                                it.contains("-----BEGIN ") && it.contains("-----END ") && it.contains(" CERTIFICATE-----")
                            }
                        }
                        var key: String? = null
                        tls.optArray("client_key")?.filterIsInstance<String>()?.also { clientKey ->
                            key = clientKey.joinToString("\n").takeIf {
                                it.contains("-----BEGIN ") && it.contains("-----END ") && it.contains(" PRIVATE KEY-----")
                            }
                        } ?: tls.optStr("client_key")?.also { clientKey ->
                            key = clientKey.takeIf {
                                it.contains("-----BEGIN ") && it.contains("-----END ") && it.contains(" PRIVATE KEY-----")
                            }
                        }
                        if (cert != null && key != null) {
                            mtlsCertificate = cert
                            mtlsCertificatePrivateKey = key
                        }
                    }
                    tls.optArray("certificate_public_key_sha256")?.filterIsInstance<String>()?.also {
                        pinnedPeerCertificatePublicKeySha256 = it.joinToString("\n")
                        allowInsecure = true
                    } ?: tls.optStr("certificate_public_key_sha256")?.also {
                        pinnedPeerCertificatePublicKeySha256 = it
                        allowInsecure = true
                    }
                } ?: return listOf()
                outbound.optObject("obfs")?.also { obfuscation ->
                    obfuscation.optStr("type")?.takeIf { it.isNotEmpty() }?.also { type ->
                        if (type != "salamander") return listOf()
                        obfuscation.optStr("password")?.also {
                            obfs = it
                        }
                    }
                }
            }
            return listOf(hysteria2Bean)
        }
        "hysteria" -> {
            val hysteriaBean = HysteriaBean().apply {
                outbound.optStringOrNull("tag")?.also {
                    name = it
                }
                outbound.optStr("server")?.also {
                    serverAddress = it
                } ?: return listOf()
                (outbound.optInteger("server_port")?.also {
                    serverPorts = it.toString()
                } ?: outbound.optArray("server_ports")?.filterIsInstance<String>()?.also {
                    serverPorts = it.joinToString(",").replace(":", "-")
                } ?: outbound.optStr("server_ports")?.also {
                    serverPorts = it.replace(":", "-")
                }) ?: return listOf()
                if (!serverPorts.isValidHysteriaPort()) {
                    return listOf()
                }
                outbound.optStr("hop_interval")?.also { interval ->
                    try {
                        val duration = Duration.parse(interval)
                        hopInterval = duration.toLong(DurationUnit.SECONDS).takeIf { it > 0 }
                    } catch (_: Exception) {}
                }
                if (outbound.optStr("auth")?.isNotEmpty() == true) {
                    authPayloadType = HysteriaBean.TYPE_BASE64
                    outbound.optStr("auth")?.also {
                        authPayload = it
                    }
                }
                if (outbound.optStr("auth_str")?.isNotEmpty() == true) {
                    authPayloadType = HysteriaBean.TYPE_STRING
                    outbound.optStr("auth_str")?.also {
                        authPayload = it
                    }
                }
                outbound.optStr("obfs")?.also {
                    obfuscation = it
                }
                outbound.optObject("tls")?.also { tls ->
                    if (tls.optBool("enabled") != true) {
                        return listOf()
                    }
                    if (tls.optObject("reality")?.optBool("enabled") == true) {
                        return listOf()
                    }
                    tls.optStr("server_name")?.also {
                        sni = it
                    }
                    tls.optArray("alpn")?.filterIsInstance<String>()?.also {
                        alpn = it[0]
                    } ?: tls.optStr("alpn")?.also {
                        alpn = it
                    }
                    tls.optBool("insecure")?.also {
                        allowInsecure = it
                    }
                } ?: return listOf()
            }
            return listOf(hysteriaBean)
        }
        "tuic" -> {
            val tuic5Bean = Tuic5Bean().apply {
                outbound.optStringOrNull("tag")?.also {
                    name = it
                }
                outbound.optStr("server")?.also {
                    serverAddress = it
                } ?: return listOf()
                outbound.optInteger("server_port")?.also {
                    serverPort = it
                } ?: return listOf()
                outbound.optStr("uuid")?.also {
                    uuid = it
                }
                outbound.optStr("password")?.also {
                    password = it
                }
                outbound.optStr("congestion_control")?.also {
                    congestionControl = if (it in supportedTuic5CongestionControl) it else "cubic"
                }
                outbound.optStr("udp_relay_mode")?.also {
                    udpRelayMode = if (it in supportedTuic5RelayMode) it else "native"
                }
                outbound.optBool("zero_rtt_handshake")?.also {
                    zeroRTTHandshake = it
                }
                outbound.optObject("tls")?.also { tls ->
                    if (tls.optBool("enabled") != true) {
                        return listOf()
                    }
                    if (tls.optObject("reality")?.optBool("enabled") == true) {
                        return listOf()
                    }
                    tls.optStr("server_name")?.also {
                        sni = it
                    }
                    tls.optArray("alpn")?.filterIsInstance<String>()?.also {
                        alpn = it.joinToString("\n")
                    } ?: tls.optStr("alpn")?.also {
                        alpn = it
                    }
                    tls.optBool("insecure")?.also {
                        allowInsecure = it
                    }
                    tls.optBool("disable_sni")?.also {
                        disableSNI = it
                    }
                    if (!tls.hasCaseInsensitive("certificate_path")) {
                        var cert: String? = null
                        tls.optArray("certificate")?.filterIsInstance<String>()?.also { certificate ->
                            cert = certificate.joinToString("\n").takeIf {
                                it.contains("-----BEGIN ") && it.contains("-----END ") && it.contains(" CERTIFICATE-----")
                            }
                        } ?: tls.optStr("certificate")?.also { certificate ->
                            cert = certificate.takeIf {
                                it.contains("-----BEGIN ") && it.contains("-----END ") && it.contains(" CERTIFICATE-----")
                            }
                        }
                        if (cert != null) {
                            certificates = cert
                        }
                    }
                    if (!tls.hasCaseInsensitive("client_certificate_path") && !tls.hasCaseInsensitive("client_key_path")) {
                        var cert: String? = null
                        tls.optArray("client_certificate")?.filterIsInstance<String>()?.also { clientCert ->
                            cert = clientCert.joinToString("\n").takeIf {
                                it.contains("-----BEGIN ") && it.contains("-----END ") && it.contains(" CERTIFICATE-----")
                            }
                        } ?: tls.optStr("client_certificate")?.also { clientCert ->
                            cert = clientCert.takeIf {
                                it.contains("-----BEGIN ") && it.contains("-----END ") && it.contains(" CERTIFICATE-----")
                            }
                        }
                        var key: String? = null
                        tls.optArray("client_key")?.filterIsInstance<String>()?.also { clientKey ->
                            key = clientKey.joinToString("\n").takeIf {
                                it.contains("-----BEGIN ") && it.contains("-----END ") && it.contains(" PRIVATE KEY-----")
                            }
                        } ?: tls.optStr("client_key")?.also { clientKey ->
                            key = clientKey.takeIf {
                                it.contains("-----BEGIN ") && it.contains("-----END ") && it.contains(" PRIVATE KEY-----")
                            }
                        }
                        if (cert != null && key != null) {
                            mtlsCertificate = cert
                            mtlsCertificatePrivateKey = key
                        }
                    }
                    tls.optArray("certificate_public_key_sha256")?.filterIsInstance<String>()?.also {
                        pinnedPeerCertificatePublicKeySha256 = it.joinToString("\n")
                        allowInsecure = true
                    } ?: tls.optStr("certificate_public_key_sha256")?.also {
                        pinnedPeerCertificatePublicKeySha256 = it
                        allowInsecure = true
                    }
                } ?: return listOf()
            }
            return listOf(tuic5Bean)
        }
        "ssh" -> {
            val sshBean = SSHBean().apply {
                outbound.optStringOrNull("tag")?.also {
                    name = it
                }
                outbound.optStr("server")?.also {
                    serverAddress = it
                } ?: return listOf()
                outbound.optInteger("server_port")?.also {
                    serverPort = it
                } ?: return listOf()
                outbound.optStr("user")?.also {
                    username = it
                }
                if (outbound.optStr("password")?.isNotEmpty() == true) {
                    authType = SSHBean.AUTH_TYPE_PASSWORD
                    outbound.optStr("password")?.also {
                        password = it
                    }
                }
                if (outbound.optStr("private_key")?.isNotEmpty() == true) {
                    authType = SSHBean.AUTH_TYPE_PRIVATE_KEY
                    outbound.optStr("private_key")?.also {
                        privateKey = it
                    }
                    outbound.optStr("private_key_passphrase")?.also {
                        privateKeyPassphrase = it
                    }
                }
                outbound.optArray("host_key")?.filterIsInstance<String>()?.also {
                    publicKey = it.joinToString("\n")
                }
            }
            return listOf(sshBean)
        }
        "ssr" -> {
            // removed in v1.6.0
            val ssrBean = ShadowsocksRBean().apply {
                outbound.optStringOrNull("tag")?.also {
                    name = it
                }
                outbound.optStr("server")?.also {
                    serverAddress = it
                } ?: return listOf()
                outbound.optInteger("server_port")?.also {
                    serverPort = it
                } ?: return listOf()
                outbound.optStr("method")?.also {
                    if (it !in supportedShadowsocksRMethod) return listOf()
                    method = it
                }
                outbound.optStr("password")?.also {
                    password = it
                }
                outbound.optStr("obfs")?.also {
                    obfs = when (it) {
                        "tls1.2_ticket_fastauth" -> "tls1.2_ticket_auth"
                        in supportedShadowsocksRObfs -> it
                        else -> return listOf()
                    }
                }
                outbound.optStr("obfs_param")?.also {
                    obfsParam = it
                }
                outbound.optStr("protocol")?.also {
                    if (it !in supportedShadowsocksRProtocol) return listOf()
                    protocol = it
                }
                outbound.optStr("protocol_param")?.also {
                    protocolParam = it
                }
            }
            return listOf(ssrBean)
        }
        "anytls" -> {
            val anytlsBean = AnyTLSBean().apply {
                outbound.optStringOrNull("tag")?.also {
                    name = it
                }
                outbound.optStr("server")?.also {
                    serverAddress = it
                } ?: return listOf()
                outbound.optInteger("server_port")?.also {
                    serverPort = it
                } ?: return listOf()
                outbound.optObject("tls")?.also { tls ->
                    (tls.optBool("enabled"))?.also { enabled ->
                        if (enabled) {
                            security = "tls"
                            tls.optStr("server_name")?.also {
                                sni = it
                            }
                            tls.optBool("insecure")?.also {
                                allowInsecure = it
                            }
                            tls.optArray("alpn")?.filterIsInstance<String>()?.also {
                                alpn = it.joinToString("\n")
                            } ?: tls.optStr("alpn")?.also {
                                alpn = it
                            }
                            if (!tls.hasCaseInsensitive("certificate_path")) {
                                var cert: String? = null
                                tls.optArray("certificate")?.filterIsInstance<String>()?.also { certificate ->
                                    cert = certificate.joinToString("\n").takeIf {
                                        it.contains("-----BEGIN ") && it.contains("-----END ") && it.contains(" CERTIFICATE-----")
                                    }
                                } ?: tls.optStr("certificate")?.also { certificate ->
                                    cert = certificate.takeIf {
                                        it.contains("-----BEGIN ") && it.contains("-----END ") && it.contains(" CERTIFICATE-----")
                                    }
                                }
                                if (cert != null) {
                                    certificates = cert
                                }
                            }
                            if (!tls.hasCaseInsensitive("client_certificate_path") && !tls.hasCaseInsensitive("client_key_path")) {
                                var cert: String? = null
                                tls.optArray("client_certificate")?.filterIsInstance<String>()?.also { clientCert ->
                                    cert = clientCert.joinToString("\n").takeIf {
                                        it.contains("-----BEGIN ") && it.contains("-----END ") && it.contains(" CERTIFICATE-----")
                                    }
                                } ?: tls.optStr("client_certificate")?.also { clientCert ->
                                    cert = clientCert.takeIf {
                                        it.contains("-----BEGIN ") && it.contains("-----END ") && it.contains(" CERTIFICATE-----")
                                    }
                                }
                                var key: String? = null
                                tls.optArray("client_key")?.filterIsInstance<String>()?.also { clientKey ->
                                    key = clientKey.joinToString("\n").takeIf {
                                        it.contains("-----BEGIN ") && it.contains("-----END ") && it.contains(" PRIVATE KEY-----")
                                    }
                                } ?: tls.optStr("client_key")?.also { clientKey ->
                                    key = clientKey.takeIf {
                                        it.contains("-----BEGIN ") && it.contains("-----END ") && it.contains(" PRIVATE KEY-----")
                                    }
                                }
                                if (cert != null && key != null) {
                                    mtlsCertificate = cert
                                    mtlsCertificatePrivateKey = key
                                }
                            }
                            tls.optArray("certificate_public_key_sha256")?.filterIsInstance<String>()?.also {
                                pinnedPeerCertificatePublicKeySha256 = it.joinToString("\n")
                                allowInsecure = true
                            } ?: tls.optStr("certificate_public_key_sha256")?.also {
                                pinnedPeerCertificatePublicKeySha256 = it
                                allowInsecure = true
                            }
                            tls.optObject("reality")?.also { reality ->
                                reality.optBool("enabled")?.also { enabled ->
                                    if (enabled) {
                                        security = "reality"
                                        reality.optStr("public_key")?.also {
                                            realityPublicKey = it
                                        }
                                        reality.optStr("short_id")?.also {
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
            if (outbound.hasCaseInsensitive("address")) {
                // wireguard endpoint format introduced in 1.11.0-alpha.19
                return listOf()
            }
            val beanList = mutableListOf<WireGuardBean>()
            val bean = WireGuardBean().apply {
                outbound.optStringOrNull("tag")?.also {
                    name = it
                }
                outbound.optStr("private_key")?.also {
                    privateKey = it
                }
                outbound.optStr("peer_public_key")?.also {
                    peerPublicKey = it
                }
                outbound.optStr("pre_shared_key")?.also {
                    peerPreSharedKey = it
                }
                mtu = 1408
                outbound.optInteger("mtu")?.takeIf { it > 0 }?.also {
                    mtu = it
                }
                outbound.optArray("local_address")?.filterIsInstance<String>()?.also {
                    localAddress = it.joinToString("\n")
                } ?: outbound.optStr("local_address")?.also {
                    localAddress = it
                } ?: return listOf()
                outbound.optArray("reserved")?.filterIsInstance<Int>()?.also {
                    if (it.size == 3) {
                        reserved = listOf(it[0].toString(), it[1].toString(), it[2].toString()).joinToString(",")
                    }
                } ?: outbound.optStr("reserved")?.also {
                    val arr = Base64.decode(it)
                    if (arr.size == 3) {
                        reserved = listOf(arr[0].toUByte().toInt().toString(), arr[1].toUByte().toInt().toString(), arr[2].toUByte().toInt().toString()).joinToString(",")
                    }
                }
            }
            if (outbound.hasCaseInsensitive("server")) {
                outbound.optStr("server")?.also {
                    bean.serverAddress = it
                } ?: return listOf()
                outbound.optInteger("server_port")?.also {
                    bean.serverPort = it
                } ?: return listOf()
                beanList.add(bean)
            }
            outbound.optArray("peers")?.filterIsInstance<JSONObject>()?.forEach { peer ->
                beanList.add(bean.applyDefaultValues().clone().apply {
                    peer.optStr("server")?.also {
                        serverAddress = it
                    }
                    peer.optInteger("server_port")?.also {
                        serverPort = it
                    }
                    peer.optStr("public_key")?.also {
                        peerPublicKey = it
                    }
                    peer.optStr("pre_shared_key")?.also {
                        peerPreSharedKey = it
                    }
                    peer.optInteger("persistent_keepalive_interval")?.takeIf { it > 0 }?.also {
                        keepaliveInterval = it
                    }
                    peer.optArray("reserved")?.filterIsInstance<Int>()?.also {
                        if (it.size == 3) {
                            reserved = listOf(it[0].toString(), it[1].toString(), it[2].toString()).joinToString(",")
                        }
                    } ?: peer.optStr("reserved")?.also {
                        val arr = Base64.decode(it)
                        if (arr.size == 3) {
                            reserved = listOf(arr[0].toUByte().toInt().toString(), arr[1].toUByte().toInt().toString(), arr[2].toUByte().toInt().toString()).joinToString(",")
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
    when (endpoint.optStringOrNull("type")) {
        "wireguard" -> {
            val beanList = mutableListOf<WireGuardBean>()
            if (endpoint.hasCaseInsensitive("local_address")) {
                // legacy wireguard outbound format
                return listOf()
            }
            val bean = WireGuardBean().apply {
                endpoint.optStringOrNull("tag")?.also {
                    name = it
                }
                endpoint.optStr("private_key")?.also {
                    privateKey = it
                }
                mtu = 1408
                endpoint.optInteger("mtu")?.takeIf { it > 0 }?.also {
                    mtu = it
                }
                endpoint.optArray("address")?.filterIsInstance<String>()?.also {
                    localAddress = it.joinToString("\n")
                } ?: endpoint.optStr("address")?.also {
                    localAddress = it
                } ?: return listOf()
            }
            endpoint.optArray("peers")?.filterIsInstance<JSONObject>()?.forEach { peer ->
                beanList.add(bean.applyDefaultValues().clone().apply {
                    peer.optStr("address")?.also {
                        serverAddress = it
                    }
                    peer.optInteger("port")?.also {
                        serverPort = it
                    }
                    peer.optStr("public_key")?.also {
                        peerPublicKey = it
                    }
                    peer.optStr("pre_shared_key")?.also {
                        peerPreSharedKey = it
                    }
                    peer.optInteger("persistent_keepalive_interval")?.takeIf { it > 0 }?.also {
                        keepaliveInterval = it
                    }
                    peer.optArray("reserved")?.filterIsInstance<Int>()?.also {
                        if (it.size == 3) {
                            reserved = listOf(it[0].toString(), it[1].toString(), it[2].toString()).joinToString(",")
                        }
                    } ?: peer.optStr("reserved")?.also {
                        val arr = Base64.decode(it)
                        if (arr.size == 3) {
                            reserved = listOf(arr[0].toUByte().toInt().toString(), arr[1].toUByte().toInt().toString(), arr[2].toUByte().toInt().toString()).joinToString(",")
                        }
                    }
                })
            }
            return beanList
        }
        else -> return listOf()
    }
}
