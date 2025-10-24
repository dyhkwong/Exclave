/******************************************************************************
 *                                                                            *
 * Copyright (C) 2023  dyhkwong                                               *
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
 * along with this program. If not, see <https://www.gnu.org/licenses/>.      *
 *                                                                            *
 ******************************************************************************/

package io.nekohasekai.sagernet.group

import com.github.shadowsocks.plugin.PluginOptions
import io.nekohasekai.sagernet.fmt.AbstractBean
import io.nekohasekai.sagernet.fmt.anytls.AnyTLSBean
import io.nekohasekai.sagernet.fmt.http.HttpBean
import io.nekohasekai.sagernet.fmt.http3.Http3Bean
import io.nekohasekai.sagernet.fmt.hysteria2.Hysteria2Bean
import io.nekohasekai.sagernet.fmt.juicity.JuicityBean
import io.nekohasekai.sagernet.fmt.juicity.supportedJuicityCongestionControl
import io.nekohasekai.sagernet.fmt.shadowsocks.ShadowsocksBean
import io.nekohasekai.sagernet.fmt.shadowsocks.supportedShadowsocks2022Method
import io.nekohasekai.sagernet.fmt.shadowsocks.supportedShadowsocksMethod
import io.nekohasekai.sagernet.fmt.socks.SOCKSBean
import io.nekohasekai.sagernet.fmt.ssh.SSHBean
import io.nekohasekai.sagernet.fmt.trojan.TrojanBean
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
import io.nekohasekai.sagernet.fmt.wireguard.WireGuardBean
import io.nekohasekai.sagernet.ktx.*
import libcore.Libcore
import org.json.JSONObject
import kotlin.collections.iterator

@Suppress("UNCHECKED_CAST")
fun parseV2RayOutbound(outbound: JSONObject): List<AbstractBean> {
    // v2ray JSONv4 config, Xray config and JSONv4 config of Exclave's v2ray fork only
    when (val proto = outbound.optStr("protocol")?.lowercase()) {
        "vmess", "vless", "trojan", "shadowsocks", "socks", "http", "shadowsocks2022", "shadowsocks-2022" -> {
            val v2rayBean = when (proto) {
                "vmess" -> VMessBean()
                "vless" -> VLESSBean()
                "trojan" -> TrojanBean()
                "shadowsocks", "shadowsocks2022", "shadowsocks-2022" -> ShadowsocksBean()
                "socks" -> SOCKSBean()
                else -> HttpBean()
            }
            outbound.optObject("streamSettings")?.also { streamSettings ->
                streamSettings.optStr("security")?.lowercase()?.also { security ->
                    when (security) {
                        "tls", "utls", "xtls" -> {
                            v2rayBean.security = "tls"
                            var tlsConfig = streamSettings.optObject("tlsSettings")
                            if (security == "utls") {
                                streamSettings.optObject("utlsSettings")?.also {
                                    tlsConfig = it.optObject("tlsConfig")
                                }
                            }
                            if (security == "xtls") { // old Xray
                                streamSettings.optObject("xtlsSettings")?.also {
                                    tlsConfig = it
                                }
                            }
                            tlsConfig?.also { tlsSettings ->
                                tlsSettings.optStr("serverName")?.also {
                                    v2rayBean.sni = it
                                }
                                tlsSettings.optArray("alpn")?.filterIsInstance<String>()?.also {
                                    v2rayBean.alpn = it.joinToString("\n")
                                } ?: tlsSettings.optStr("alpn")?.also {
                                    v2rayBean.alpn = it.split(",").joinToString("\n")
                                }
                                tlsSettings.optBool("allowInsecure")?.also {
                                    v2rayBean.allowInsecure = it
                                }
                                tlsSettings.optArray("certificates")?.filterIsInstance<JSONObject>()?.asReversed()?.forEach { certificate ->
                                    when (certificate.optStr("usage")?.lowercase()) {
                                        null, "", "encipherment" -> {
                                            if (!certificate.hasCaseInsensitive("certificateFile") && !certificate.hasCaseInsensitive("keyFile")) {
                                                val cert = certificate.optArray("certificate")?.filterIsInstance<String>()?.joinToString("\n")?.takeIf {
                                                    it.contains("-----BEGIN ") && it.contains("-----END ") && it.contains(" CERTIFICATE-----")
                                                }
                                                val key = certificate.optArray("key")?.filterIsInstance<String>()?.joinToString("\n")?.takeIf {
                                                    it.contains("-----BEGIN ") && it.contains("-----END ") && it.contains(" PRIVATE KEY-----")
                                                }
                                                if (cert != null && key != null) {
                                                    v2rayBean.mtlsCertificate = cert
                                                    v2rayBean.mtlsCertificatePrivateKey = key
                                                }
                                            }
                                        }
                                        "verify" -> {
                                            if (!certificate.hasCaseInsensitive("certificateFile")) {
                                                val cert = certificate.optArray("certificate")?.filterIsInstance<String>()?.joinToString("\n")?.takeIf {
                                                    it.contains("-----BEGIN ") && it.contains("-----END ") && it.contains(" CERTIFICATE-----")
                                                }
                                                if (cert != null) {
                                                    v2rayBean.certificates = cert
                                                }
                                            }
                                        }
                                    }
                                }
                                tlsSettings.optArray("pinnedPeerCertificateChainSha256")?.filterIsInstance<String>()?.also {
                                    v2rayBean.pinnedPeerCertificateChainSha256 = it.joinToString("\n")
                                    tlsSettings.optBool("allowInsecureIfPinnedPeerCertificate")?.also { allowInsecure ->
                                        v2rayBean.allowInsecure = allowInsecure
                                    }
                                }
                                tlsSettings.optArray("pinnedPeerCertificatePublicKeySha256")?.filterIsInstance<String>()?.also {
                                    v2rayBean.pinnedPeerCertificatePublicKeySha256 = it.joinToString("\n")
                                    tlsSettings.optBool("allowInsecureIfPinnedPeerCertificate")?.also { allowInsecure ->
                                        v2rayBean.allowInsecure = allowInsecure
                                    }
                                }
                                tlsSettings.optArray("pinnedPeerCertificateSha256")?.filterIsInstance<String>()?.also {
                                    v2rayBean.pinnedPeerCertificateSha256 = it.joinToString("\n")
                                    tlsSettings.optBool("allowInsecureIfPinnedPeerCertificate")?.also { allowInsecure ->
                                        v2rayBean.allowInsecure = allowInsecure
                                    }
                                }
                            }
                        }
                        "reality" -> {
                            v2rayBean.security = "reality"
                            streamSettings.optObject("realitySettings")?.also { realitySettings ->
                                realitySettings.optStr("serverName")?.also {
                                    v2rayBean.sni = it
                                }
                                realitySettings.optStr("publicKey")?.also {
                                    v2rayBean.realityPublicKey = it
                                }
                                realitySettings.optStr("shortId")?.also {
                                    v2rayBean.realityShortId = it
                                }
                            }
                        }
                    }
                }
                streamSettings.optStr("network")?.lowercase()?.also { network ->
                    when (network) {
                        "tcp", "raw" -> {
                            v2rayBean.type = "tcp"
                            (streamSettings.optObject("tcpSettings") ?: streamSettings.optObject("rawSettings"))?.also { tcpSettings ->
                                tcpSettings.optObject("header")?.also { header ->
                                    header.optStr("type")?.lowercase()?.also { type ->
                                        when (type) {
                                            "none" -> {}
                                            "http" -> {
                                                v2rayBean.headerType = "http"
                                                header.optObject("request")?.also { request ->
                                                    request.optArray("path")?.filterIsInstance<String>()?.also {
                                                        v2rayBean.path = it.joinToString("\n")
                                                    } ?: request.optStr("path")?.also {
                                                        v2rayBean.path = it.split(",").joinToString("\n")
                                                    }
                                                    request.optObject("headers")?.also { headers ->
                                                        headers.optArray("Host")?.filterIsInstance<String>()?.also {
                                                            v2rayBean.host = it.joinToString("\n")
                                                        } ?: headers.optStr("Host")?.also {
                                                            v2rayBean.host = it.split(",").joinToString("\n")
                                                        }
                                                    }
                                                }
                                            }
                                            else -> return listOf()
                                        }
                                    }
                                }
                            }
                        }
                        "kcp", "mkcp" -> {
                            v2rayBean.type = "kcp"
                            streamSettings.optObject("kcpSettings")?.also { kcpSettings ->
                                kcpSettings.optStr("seed")?.also {
                                    v2rayBean.mKcpSeed = it
                                }
                                kcpSettings.optObject("header")?.also { header ->
                                    header.optStr("type")?.lowercase()?.also {
                                        if (it !in supportedKcpQuicHeaderType) return listOf()
                                        v2rayBean.headerType = it
                                    }
                                }
                            }
                        }
                        "ws", "websocket" -> {
                            v2rayBean.type = "ws"
                            streamSettings.optObject("wsSettings")?.also { wsSettings ->
                                wsSettings.optObject("headers")?.also {
                                    v2rayBean.host = it.optStr("host")
                                }
                                wsSettings.optStr("host")?.also {
                                    // Xray has a separate field of Host header
                                    // will not follow the breaking change in
                                    // https://github.com/XTLS/Xray-core/commit/a2b773135a860f63e990874c551b099dfc888471
                                    v2rayBean.host = it
                                }
                                wsSettings.optInteger("maxEarlyData")?.also {
                                    v2rayBean.maxEarlyData = it
                                }
                                wsSettings.optStr("earlyDataHeaderName")?.also {
                                    v2rayBean.earlyDataHeaderName = it
                                }
                                wsSettings.optStr("path")?.also { path ->
                                    v2rayBean.path = path
                                    try {
                                        // RPRX's smart-assed invention. This of course will break under some conditions.
                                        val u = Libcore.parseURL(path)
                                        u.queryParameter("ed")?.also { ed ->
                                            u.deleteQueryParameter("ed")
                                            v2rayBean.path = u.string
                                            ed.toIntOrNull()?.also {
                                                v2rayBean.maxEarlyData = it
                                            }
                                            v2rayBean.earlyDataHeaderName = "Sec-WebSocket-Protocol"
                                        }
                                    } catch (_: Exception) {}
                                }
                            }
                        }
                        "http", "h2" -> {
                            v2rayBean.type = "http"
                            streamSettings.optObject("httpSettings")?.also { httpSettings ->
                                // will not follow the breaking change in
                                // https://github.com/XTLS/Xray-core/commit/0a252ac15d34e7c23a1d3807a89bfca51cbb559b
                                httpSettings.optArray("host")?.filterIsInstance<String>()?.also {
                                    v2rayBean.host = it.joinToString("\n")
                                } ?: httpSettings.optStr("host")?.also {
                                    v2rayBean.host = it.split(",").joinToString("\n")
                                }
                                httpSettings.optStr("path")?.also {
                                    v2rayBean.path = it
                                }
                            }
                        }
                        "quic" -> {
                            v2rayBean.type = "quic"
                            streamSettings.optObject("quicSettings")?.also { quicSettings ->
                                quicSettings.optStr("security")?.lowercase()?.also {
                                    if (it !in supportedQuicSecurity) return listOf()
                                    v2rayBean.quicSecurity = it
                                }
                                quicSettings.optStr("key")?.also {
                                    v2rayBean.quicKey = it
                                }
                                quicSettings.optObject("header")?.also { header ->
                                    header.optStr("type")?.lowercase()?.also {
                                        if (it !in supportedKcpQuicHeaderType) return listOf()
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
                            (streamSettings.optObject("grpcSettings") ?: streamSettings.optObject("gunSettings"))?.also { grpcSettings ->
                                grpcSettings.optStr("serviceName")?.also {
                                    v2rayBean.grpcServiceName = it
                                }
                            }
                        }
                        "httpupgrade" -> {
                            v2rayBean.type = "httpupgrade"
                            streamSettings.optObject("httpupgradeSettings")?.also { httpupgradeSettings ->
                                httpupgradeSettings.optStr("host")?.also {
                                    // will not follow the breaking change in
                                    // https://github.com/XTLS/Xray-core/commit/a2b773135a860f63e990874c551b099dfc888471
                                    v2rayBean.host = it
                                }
                                httpupgradeSettings.optStr("path")?.also {
                                    v2rayBean.path = it
                                    try {
                                        // RPRX's smart-assed invention. This of course will break under some conditions.
                                        val u = Libcore.parseURL(it)
                                        u.queryParameter("ed")?.also {
                                            u.deleteQueryParameter("ed")
                                            v2rayBean.path = u.string
                                        }
                                    } catch (_: Exception) {}
                                }
                                httpupgradeSettings.optInteger("maxEarlyData")?.also {
                                    v2rayBean.maxEarlyData = it
                                }
                                httpupgradeSettings.optStr("earlyDataHeaderName")?.also {
                                    v2rayBean.earlyDataHeaderName = it
                                }
                            }
                        }
                        "meek" -> {
                            v2rayBean.type = "meek"
                            streamSettings.optObject("meekSettings")?.also { meekSettings ->
                                meekSettings.optStr("url")?.also {
                                    v2rayBean.meekUrl = it
                                }
                            }
                        }
                        "mekya" -> {
                            v2rayBean.type = "mekya"
                            streamSettings.optObject("mekyaSettings")?.also { mekyaSettings ->
                                mekyaSettings.optStr("url")?.also {
                                    v2rayBean.mekyaUrl = it
                                }
                                mekyaSettings.optObject("kcp")?.also { kcp ->
                                    kcp.optStr("seed")?.also {
                                        v2rayBean.mekyaKcpSeed = it
                                    }
                                    kcp.optObject("header")?.also { header ->
                                        header.optStr("type")?.lowercase()?.also {
                                            if (it !in supportedKcpQuicHeaderType) return listOf()
                                            v2rayBean.mekyaKcpHeaderType = it
                                        }
                                    }
                                }
                            }
                        }
                        "splithttp", "xhttp" -> {
                            v2rayBean.type = "splithttp"
                            (streamSettings.optObject("splithttpSettings") ?: streamSettings.optObject("xhttpSettings"))?.also { splithttpSettings ->
                                splithttpSettings.optStr("host")?.also {
                                    v2rayBean.host = it
                                }
                                splithttpSettings.optStr("path")?.also {
                                    v2rayBean.path = it
                                }
                                splithttpSettings.optStr("mode")?.also {
                                    v2rayBean.splithttpMode = when (it) {
                                        in supportedXhttpMode -> it
                                        "" -> "auto"
                                        else -> return listOf()
                                    }
                                }
                                // fuck RPRX `extra`
                                var extra = JSONObject()
                                splithttpSettings.optObject("extra")?.also {
                                    extra = it
                                }
                                if (!extra.hasCaseInsensitive("scMaxEachPostBytes")) {
                                    splithttpSettings.optInteger("scMaxEachPostBytes")?.also {
                                        extra.put("scMaxEachPostBytes", it)
                                    } ?: splithttpSettings.optStr("scMaxEachPostBytes")?.also {
                                        extra.put("scMaxEachPostBytes", it)
                                    }
                                }
                                if (!extra.hasCaseInsensitive("scMinPostsIntervalMs")) {
                                    splithttpSettings.optInteger("scMinPostsIntervalMs")?.also {
                                        extra.put("scMinPostsIntervalMs", it)
                                    } ?: splithttpSettings.optStr("scMinPostsIntervalMs")?.also {
                                        extra.put("scMinPostsIntervalMs", it)
                                    }
                                }
                                if (!extra.hasCaseInsensitive("xPaddingBytes")) {
                                    splithttpSettings.optInteger("xPaddingBytes")?.also {
                                        extra.put("xPaddingBytes", it)
                                    } ?: splithttpSettings.optStr("xPaddingBytes")?.also {
                                        extra.put("xPaddingBytes", it)
                                    }
                                }
                                if (!extra.hasCaseInsensitive("noGRPCHeader")) {
                                    splithttpSettings.optBool("noGRPCHeader")?.also {
                                        extra.put("noGRPCHeader", it)
                                    }
                                }
                                if (extra.length() > 0) {
                                    v2rayBean.splithttpExtra = extra.toString()
                                }
                            }
                        }
                        "hysteria2", "hy2" -> {
                            v2rayBean.type = "hysteria2"
                            streamSettings.optObject("hy2Settings")?.also { hy2Settings ->
                                hy2Settings.optStr("password")?.also {
                                    v2rayBean.hy2Password = it
                                }
                                hy2Settings.optObject("obfs")?.also { obfs ->
                                    obfs.optStr("type")?.also { type ->
                                        if (type == "salamander") {
                                            return listOf()
                                        }
                                    }
                                }
                            }
                        }
                        else -> return listOf()
                    }
                }
            }
            when (proto) {
                "vmess" -> {
                    v2rayBean as VMessBean
                    (outbound.optStr("tag"))?.also {
                        v2rayBean.name = it
                    }
                    outbound.optObject("settings")?.also { settings ->
                        v2rayBean.packetEncoding = when (settings.optStr("packetEncoding")?.lowercase()) {
                            "xudp" -> "xudp"
                            "packet" -> "packet"
                            else -> "none"
                        }
                        settings.optStr("address")?.also { address ->
                            v2rayBean.serverAddress = address
                            settings.optV2RayPort("port")?.also {
                                v2rayBean.serverPort = it
                            } ?: return listOf()
                            settings.optStr("id")?.also {
                                v2rayBean.uuid = uuidOrGenerate(it)
                            }
                            settings.optStr("security")?.lowercase()?.also {
                                if (it !in supportedVmessMethod) return listOf()
                                v2rayBean.encryption = it
                            }
                            settings.optInteger("alterId")?.also {
                                v2rayBean.alterId = it
                            }
                            settings.optStr("experiments")?.also {
                                if (it.contains("AuthenticatedLength")) {
                                    v2rayBean.experimentalAuthenticatedLength = true
                                }
                                if (it.contains("NoTerminationSignal")) {
                                    v2rayBean.experimentalNoTerminationSignal = true
                                }
                            }
                        } ?: settings.optArray("vnext")?.filterIsInstance<JSONObject>()?.get(0)?.also { vnext ->
                            vnext.optStr("address")?.also {
                                v2rayBean.serverAddress = it
                            } ?: return listOf()
                            vnext.optV2RayPort("port")?.also {
                                v2rayBean.serverPort = it
                            } ?: return listOf()
                            vnext.optArray("users")?.filterIsInstance<JSONObject>()?.get(0)?.also { user ->
                                user.optStr("id")?.also {
                                    v2rayBean.uuid = uuidOrGenerate(it)
                                }
                                user.optStr("security")?.lowercase()?.also {
                                    if (it !in supportedVmessMethod) return listOf()
                                    v2rayBean.encryption = it
                                }
                                user.optInteger("alterId")?.also {
                                    v2rayBean.alterId = it
                                }
                                user.optStr("experiments")?.also {
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
                    (outbound.optStr("tag"))?.also {
                        v2rayBean.name = it
                    }
                    outbound.optObject("settings")?.also { settings ->
                        v2rayBean.packetEncoding = when (settings.optStr("packetEncoding")?.lowercase()) {
                            "xudp" -> "xudp"
                            "packet" -> "packet"
                            else -> "none"
                        }
                        settings.optStr("address")?.also { address ->
                            settings.optStr("reverse")?.also {
                                return listOf()
                            }
                            v2rayBean.serverAddress = address
                            settings.optV2RayPort("port")?.also {
                                v2rayBean.serverPort = it
                            } ?: return listOf()
                            settings.optStr("id")?.also {
                                v2rayBean.uuid = uuidOrGenerate(it)
                            }
                            settings.optStr("flow")?.also {
                                when (it) {
                                    in supportedVlessFlow -> {
                                        v2rayBean.flow = "xtls-rprx-vision-udp443"
                                        v2rayBean.packetEncoding = "xudp"
                                    }
                                    in legacyVlessFlow,  "", "none" -> {}
                                    else -> if (it.startsWith("xtls-rprx-")) return listOf()
                                }
                            }
                            when (val encryption = settings.optStr("encryption")) {
                                "none" -> v2rayBean.encryption = "none"
                                "", null -> return listOf()
                                else -> {
                                    val parts = encryption.split(".")
                                    if (parts.size < 4 || parts[0] != "mlkem768x25519plus"
                                        || !(parts[1] == "native" || parts[1] == "xorpub" || parts[1] != "random")
                                        || !(parts[2] == "1rtt" || parts[2] == "0rtt")) {
                                        error("unsupported vless encryption")
                                    }
                                    v2rayBean.encryption = encryption
                                }
                            }
                        } ?: settings.optArray("vnext")?.filterIsInstance<JSONObject>()?.get(0)?.also { vnext ->
                            vnext.optStr("reverse")?.also {
                                return listOf()
                            }
                            vnext.optStr("address")?.also {
                                v2rayBean.serverAddress = it
                            } ?: return listOf()
                            vnext.optV2RayPort("port")?.also {
                                v2rayBean.serverPort = it
                            } ?: return listOf()
                            vnext.optArray("users")?.filterIsInstance<JSONObject>()?.get(0)?.also { user ->
                                user.optStr("id")?.also {
                                    v2rayBean.uuid = uuidOrGenerate(it)
                                }
                                user.optStr("flow")?.also {
                                    when (it) {
                                        in supportedVlessFlow -> {
                                            v2rayBean.flow = "xtls-rprx-vision-udp443"
                                            v2rayBean.packetEncoding = "xudp"
                                        }
                                        in legacyVlessFlow,  "", "none" -> {}
                                        else -> if (it.startsWith("xtls-rprx-")) return listOf()
                                    }
                                }
                                when (val encryption = user.optStr("encryption")) {
                                    "none" -> v2rayBean.encryption = "none"
                                    "", null -> return listOf()
                                    else -> {
                                        val parts = encryption.split(".")
                                        if (parts.size < 4 || parts[0] != "mlkem768x25519plus"
                                            || !(parts[1] == "native" || parts[1] == "xorpub" || parts[1] != "random")
                                            || !(parts[2] == "1rtt" || parts[2] == "0rtt")) {
                                            error("unsupported vless encryption")
                                        }
                                        v2rayBean.encryption = encryption
                                    }
                                }
                            }
                        }
                    }
                }
                "shadowsocks" -> {
                    v2rayBean as ShadowsocksBean
                    outbound.optStr("tag")?.also {
                        v2rayBean.name = it
                    }
                    outbound.optObject("settings")?.also { settings ->
                        settings.optStr("address")?.also { address ->
                            v2rayBean.serverAddress = address
                            settings.optV2RayPort("port")?.also {
                                v2rayBean.serverPort = it
                            } ?: return listOf()
                            settings.optStr("method")?.lowercase()?.also {
                                v2rayBean.method = when (it) {
                                    in supportedShadowsocksMethod -> it
                                    "aes_128_gcm", "aead_aes_128_gcm" -> "aes-128-gcm"
                                    "aes_192_gcm", "aead_aes_192_gcm" -> "aes-192-gcm"
                                    "aes_256_gcm", "aead_aes_256_gcm" -> "aes-256-gcm"
                                    "chacha20_poly1305", "aead_chacha20_poly1305", "chacha20-poly1305" -> "chacha20-ietf-poly1305"
                                    "xchacha20_poly1305", "aead_xchacha20_poly1305", "xchacha20-poly1305" -> "xchacha20-ietf-poly1305"
                                    "plain" -> "none"
                                    else -> return listOf()
                                }
                            }
                            settings.optStr("password")?.also {
                                v2rayBean.password = it
                            }
                            settings.optStr("plugin")?.also { pluginId ->
                                v2rayBean.plugin = PluginOptions(pluginId, settings.optStr("pluginOpts")).toString(trimId = false)
                            }
                        } ?: settings.optArray("servers")?.filterIsInstance<JSONObject>()?.get(0)?.also { server ->
                            settings.optStr("plugin")?.also { pluginId ->
                                v2rayBean.plugin = PluginOptions(pluginId, settings.optStr("pluginOpts")).toString(trimId = false)
                            }
                            server.optStr("address")?.also {
                                v2rayBean.serverAddress = it
                            } ?: return listOf()
                            server.optV2RayPort("port")?.also {
                                v2rayBean.serverPort = it
                            } ?: return listOf()
                            server.optStr("method")?.lowercase()?.also {
                                v2rayBean.method = when (it) {
                                    in supportedShadowsocksMethod -> it
                                    "aes_128_gcm", "aead_aes_128_gcm" -> "aes-128-gcm"
                                    "aes_192_gcm", "aead_aes_192_gcm" -> "aes-192-gcm"
                                    "aes_256_gcm", "aead_aes_256_gcm" -> "aes-256-gcm"
                                    "chacha20_poly1305", "aead_chacha20_poly1305", "chacha20-poly1305" -> "chacha20-ietf-poly1305"
                                    "xchacha20_poly1305", "aead_xchacha20_poly1305", "xchacha20-poly1305" -> "xchacha20-ietf-poly1305"
                                    "plain" -> "none"
                                    else -> return listOf()
                                }
                            }
                            server.optStr("password")?.also {
                                v2rayBean.password = it
                            }
                        }
                    }
                }
                "shadowsocks2022" -> {
                    v2rayBean as ShadowsocksBean
                    outbound.optStr("tag")?.also {
                        v2rayBean.name = it
                    }
                    outbound.optObject("settings")?.also { settings ->
                        settings.optStr("address")?.also {
                            v2rayBean.serverAddress = it
                        } ?: return listOf()
                        settings.optV2RayPort("port")?.also {
                            v2rayBean.serverPort = it
                        } ?: return listOf()
                        settings.optStr("method")?.lowercase()?.also {
                            if (it !in supportedShadowsocks2022Method) return listOf()
                            v2rayBean.method = it
                        }
                        settings.optStr("psk")?.also { psk ->
                            v2rayBean.password = psk
                            (settings.optArray("ipsk")?.filterIsInstance<String>())?.also { ipsk ->
                                v2rayBean.password = ipsk.joinToString(":") + ":" + psk
                            }
                        }
                        settings.optStr("plugin")?.also { pluginId ->
                            v2rayBean.plugin = PluginOptions(pluginId, settings.optStr("pluginOpts")).toString(trimId = false)
                        }
                    }
                }
                "shadowsocks-2022" -> {
                    v2rayBean as ShadowsocksBean
                    outbound.optStr("tag")?.also {
                        v2rayBean.name = it
                    }
                    outbound.optObject("settings")?.also { settings ->
                        settings.optStr("address")?.also {
                            v2rayBean.serverAddress = it
                        } ?: return listOf()
                        settings.optV2RayPort("port")?.also {
                            v2rayBean.serverPort = it
                        } ?: return listOf()
                        settings.optStr("method")?.lowercase()?.also {
                            if (it !in supportedShadowsocks2022Method) return listOf()
                            v2rayBean.method = it
                        }
                        settings.optStr("password")?.also {
                            v2rayBean.password = it
                        }
                        settings.optStr("plugin")?.also { pluginId ->
                            v2rayBean.plugin = PluginOptions(pluginId, settings.optStr("pluginOpts")).toString(trimId = false)
                        }
                    }
                }
                "trojan" -> {
                    v2rayBean as TrojanBean
                    outbound.optStr("tag")?.also {
                        v2rayBean.name = it
                    }
                    outbound.optObject("settings")?.also { settings ->
                        settings.optStr("address")?.also { address ->
                            v2rayBean.serverAddress = address
                            settings.optV2RayPort("port")?.also {
                                v2rayBean.serverPort = it
                            } ?: return listOf()
                            settings.optStr("password")?.also {
                                v2rayBean.password = it
                            }
                        } ?: settings.optArray("servers")?.filterIsInstance<JSONObject>()?.get(0)?.also { server ->
                            server.optStr("address")?.also {
                                v2rayBean.serverAddress = it
                            } ?: return listOf()
                            server.optV2RayPort("port")?.also {
                                v2rayBean.serverPort = it
                            } ?: return listOf()
                            server.optStr("password")?.also {
                                v2rayBean.password = it
                            }
                        }
                    }
                }
                "socks" -> {
                    v2rayBean as SOCKSBean
                    outbound.optStr("tag")?.also {
                        v2rayBean.name = it
                    }
                    outbound.optObject("settings")?.also { settings ->
                        v2rayBean.protocol = when (settings.optStr("version")?.lowercase()) {
                            "4" -> SOCKSBean.PROTOCOL_SOCKS4
                            "4a" -> SOCKSBean.PROTOCOL_SOCKS4A
                            "", "5" -> SOCKSBean.PROTOCOL_SOCKS5
                            else -> return listOf()
                        }
                        settings.optStr("address")?.also { address ->
                            v2rayBean.serverAddress = address
                            settings.optV2RayPort("port")?.also {
                                v2rayBean.serverPort = it
                            } ?: return listOf()
                            settings.optStr("user")?.also {
                                v2rayBean.username = it
                            }
                            settings.optStr("pass")?.also {
                                v2rayBean.password = it
                            }
                        } ?: settings.optArray("servers")?.filterIsInstance<JSONObject>()?.get(0)?.also { server ->
                            server.optStr("address")?.also {
                                v2rayBean.serverAddress = it
                            } ?: return listOf()
                            server.optV2RayPort("port")?.also {
                                v2rayBean.serverPort = it
                            } ?: return listOf()
                            server.optArray("users")?.filterIsInstance<JSONObject>()?.get(0)?.also { user ->
                                user.optStr("user")?.also {
                                    v2rayBean.username = it
                                }
                                user.optStr("pass")?.also {
                                    v2rayBean.password = it
                                }
                            }
                        }
                    }
                }
                "http" -> {
                    v2rayBean as HttpBean
                    outbound.optStr("tag")?.also {
                        v2rayBean.name = it
                    }
                    outbound.optObject("settings")?.also { settings ->
                        settings.optStr("address")?.also { address ->
                            v2rayBean.serverAddress = address
                            settings.optV2RayPort("port")?.also {
                                v2rayBean.serverPort = it
                            } ?: return listOf()
                            settings.optStr("user")?.also {
                                v2rayBean.username = it
                            }
                            settings.optStr("pass")?.also {
                                v2rayBean.password = it
                            }
                        } ?: settings.optArray("servers")?.filterIsInstance<JSONObject>()?.get(0)?.also { server ->
                            server.optStr("address")?.also {
                                v2rayBean.serverAddress = it
                            } ?: return listOf()
                            server.optV2RayPort("port")?.also {
                                v2rayBean.serverPort = it
                            } ?: return listOf()
                            server.optArray("users")?.filterIsInstance<JSONObject>()?.get(0)?.also { user ->
                                user.optStr("user")?.also {
                                    v2rayBean.username = it
                                }
                                user.optStr("pass")?.also {
                                    v2rayBean.password = it
                                }
                            }
                        }
                    }
                }
            }
            return listOf(v2rayBean)
        }
        "hysteria2" -> {
            val hysteria2Bean = Hysteria2Bean()
            outbound.optStr("tag")?.also {
                hysteria2Bean.name = it
            }
            outbound.optObject("settings")?.also { settings ->
                settings.optStr("address")?.also { address ->
                    hysteria2Bean.serverAddress = address
                    settings.optV2RayPort("port")?.also {
                        hysteria2Bean.serverPorts = it.toString()
                    } ?: return listOf()
                } ?: settings.optArray("servers")?.filterIsInstance<JSONObject>()?.get(0)?.also { server ->
                    server.optStr("address")?.also {
                        hysteria2Bean.serverAddress = it
                    } ?: return listOf()
                    server.optV2RayPort("port")?.also {
                        hysteria2Bean.serverPorts = it.toString()
                    } ?: return listOf()
                }
            }
            outbound.optObject("streamSettings")?.also { streamSettings ->
                streamSettings.optStr("network")?.lowercase()?.also { network ->
                    when (network) {
                        "hysteria2", "hy2" -> {
                            streamSettings.optObject("hy2Settings")?.also { hy2Settings ->
                                hy2Settings.optStr("password")?.also {
                                    hysteria2Bean.auth = it
                                }
                                hy2Settings.optObject("obfs")?.also { obfs ->
                                    obfs.optStr("type")?.also { type ->
                                        if (type == "salamander") {
                                            obfs.optStr("password")?.also {
                                                hysteria2Bean.obfs = it
                                            }
                                        }
                                    }
                                }
                                hy2Settings.optStr("hopPorts")?.takeIf { it.isValidHysteriaMultiPort() }?.also {
                                    hysteria2Bean.serverPorts = it
                                }
                                hy2Settings.optLongInteger("hopInterval")?.also {
                                    hysteria2Bean.hopInterval = it.takeIf { it > 0 }
                                }
                            }
                        }
                        else -> return listOf()
                    }
                }
                streamSettings.optStr("security")?.lowercase()?.also { security ->
                    when (security) {
                        "tls" -> {
                            streamSettings.optObject("tlsSettings")?.also { tlsSettings ->
                                tlsSettings.optStr("serverName")?.also {
                                    hysteria2Bean.sni = it
                                }
                                tlsSettings.optBool("allowInsecure")?.also {
                                    hysteria2Bean.allowInsecure = it
                                }
                                tlsSettings.optArray("certificates")?.filterIsInstance<JSONObject>()?.asReversed()?.forEach { certificate ->
                                    when (certificate.optStr("usage")?.lowercase()) {
                                        null, "", "encipherment" -> {
                                            if (!certificate.hasCaseInsensitive("certificateFile") && !certificate.hasCaseInsensitive("keyFile")) {
                                                val cert = certificate.optArray("certificate")?.filterIsInstance<String>()?.joinToString("\n")?.takeIf {
                                                    it.contains("-----BEGIN ") && it.contains("-----END ") && it.contains(" CERTIFICATE-----")
                                                }
                                                val key = certificate.optArray("key")?.filterIsInstance<String>()?.joinToString("\n")?.takeIf {
                                                    it.contains("-----BEGIN ") && it.contains("-----END ") && it.contains(" PRIVATE KEY-----")
                                                }
                                                if (cert != null && key != null) {
                                                    hysteria2Bean.mtlsCertificate = cert
                                                    hysteria2Bean.mtlsCertificatePrivateKey = key
                                                }
                                            }
                                        }
                                        "verify" -> {
                                            if (!certificate.hasCaseInsensitive("certificateFile")) {
                                                val cert = certificate.optArray("certificate")?.filterIsInstance<String>()?.joinToString("\n")?.takeIf {
                                                    it.contains("-----BEGIN ") && it.contains("-----END ") && it.contains(" CERTIFICATE-----")
                                                }
                                                if (cert != null) {
                                                    hysteria2Bean.certificates = cert
                                                }
                                            }
                                        }
                                    }
                                }
                                tlsSettings.optArray("pinnedPeerCertificateChainSha256")?.filterIsInstance<String>()?.also {
                                    hysteria2Bean.pinnedPeerCertificateChainSha256 = it.joinToString("\n")
                                    tlsSettings.optBool("allowInsecureIfPinnedPeerCertificate")?.also { allowInsecure ->
                                        hysteria2Bean.allowInsecure = allowInsecure
                                    }
                                }
                                tlsSettings.optArray("pinnedPeerCertificatePublicKeySha256")?.filterIsInstance<String>()?.also {
                                    hysteria2Bean.pinnedPeerCertificatePublicKeySha256 = it.joinToString("\n")
                                    tlsSettings.optBool("allowInsecureIfPinnedPeerCertificate")?.also { allowInsecure ->
                                        hysteria2Bean.allowInsecure = allowInsecure
                                    }
                                }
                                tlsSettings.optArray("pinnedPeerCertificateSha256")?.filterIsInstance<String>()?.also {
                                    hysteria2Bean.pinnedPeerCertificateSha256 = it.joinToString("\n")
                                    tlsSettings.optBool("allowInsecureIfPinnedPeerCertificate")?.also { allowInsecure ->
                                        hysteria2Bean.allowInsecure = allowInsecure
                                    }
                                }
                            }
                        }
                        else -> return listOf()
                    }
                }
            }
            return listOf(hysteria2Bean)
        }
        "ssh" -> {
            outbound.optObject("streamSettings")?.also { streamSettings ->
                streamSettings.optStr("network")?.lowercase()?.also {
                    if (it in nonRawTransportName) return listOf()
                }
                streamSettings.optStr("security")?.lowercase()?.also {
                    if (it != "none") return listOf()
                }
            }
            val sshBean = SSHBean()
            outbound.optObject("settings")?.also { settings ->
                outbound.optStr("tag")?.also {
                    sshBean.name = it
                }
                settings.optStr("address")?.also {
                    sshBean.serverAddress = it
                } ?: return listOf()
                settings.optV2RayPort("port")?.also {
                    sshBean.serverPort = it
                } ?: return listOf()
                settings.optStr("user")?.also {
                    sshBean.username = it
                }
                settings.optStr("publicKey")?.also {
                    sshBean.publicKey = it
                }
                settings.optStr("privateKey")?.also {
                    sshBean.authType = SSHBean.AUTH_TYPE_PRIVATE_KEY
                    sshBean.privateKey = it
                    settings.optStr("password")?.also { pass ->
                        sshBean.privateKeyPassphrase = pass
                    }
                } ?: settings.optStr("password")?.also {
                    sshBean.authType = SSHBean.AUTH_TYPE_PASSWORD
                    sshBean.password = it
                }
            }
            return listOf(sshBean)
        }
        "tuic" -> {
            val tuic5Bean = Tuic5Bean()
            outbound.optObject("settings")?.also { settings ->
                outbound.optStr("tag")?.also {
                    tuic5Bean.name = it
                }
                settings.optStr("address")?.also {
                    tuic5Bean.serverAddress = it
                } ?: return listOf()
                settings.optV2RayPort("port")?.also {
                    tuic5Bean.serverPort = it
                } ?: return listOf()
                settings.optStr("uuid")?.also {
                    tuic5Bean.uuid = it
                }
                settings.optStr("password")?.also {
                    tuic5Bean.password = it
                }
                settings.optStr("congestionControl")?.also {
                    tuic5Bean.congestionControl = if (it in supportedTuic5CongestionControl) it else "cubic"
                }
                settings.optStr("udpRelayMode")?.also {
                    tuic5Bean.udpRelayMode = if (it in supportedTuic5RelayMode) it else "native"
                }
                settings.optBool("zeroRTTHandshake")?.also {
                    tuic5Bean.zeroRTTHandshake = it
                }
                settings.optObject("tlsSettings")?.also { tlsSettings ->
                    tlsSettings.optStr("serverName")?.also {
                        tuic5Bean.sni = it
                    }
                    tlsSettings.optBool("allowInsecure")?.also {
                        tuic5Bean.allowInsecure = it
                    }
                    tlsSettings.optArray("alpn")?.filterIsInstance<String>()?.also {
                        tuic5Bean.alpn = it.joinToString("\n")
                    } ?: tlsSettings.optStr("alpn")?.also {
                        tuic5Bean.alpn = it.split(",").joinToString("\n")
                    }
                }
                settings.optBool("disableSNI")?.also {
                    tuic5Bean.disableSNI = it
                }
            }
            return listOf(tuic5Bean)
        }
        "http3" -> {
            val http3Bean = Http3Bean()
            outbound.optObject("settings")?.also { settings ->
                outbound.optStr("tag")?.also {
                    http3Bean.name = it
                }
                settings.optStr("address")?.also {
                    http3Bean.serverAddress = it
                } ?: return listOf()
                settings.optV2RayPort("port")?.also {
                    http3Bean.serverPort = it
                } ?: return listOf()
                settings.optStr("username")?.also {
                    http3Bean.username = it
                }
                settings.optStr("password")?.also {
                    http3Bean.password = it
                }
                settings.optObject("tlsSettings")?.also { tlsSettings ->
                    tlsSettings.optStr("serverName")?.also {
                        http3Bean.sni = it
                    }
                    tlsSettings.optBool("allowInsecure")?.also {
                        http3Bean.allowInsecure = it
                    }
                    tlsSettings.optArray("certificates")?.filterIsInstance<JSONObject>()?.asReversed()?.forEach { certificate ->
                        when (certificate.optStr("usage")?.lowercase()) {
                            null, "", "encipherment" -> {
                                if (!certificate.hasCaseInsensitive("certificateFile") && !certificate.hasCaseInsensitive("keyFile")) {
                                    val cert = certificate.optArray("certificate")?.filterIsInstance<String>()?.joinToString("\n")?.takeIf {
                                        it.contains("-----BEGIN ") && it.contains("-----END ") && it.contains(" CERTIFICATE-----")
                                    }
                                    val key = certificate.optArray("key")?.filterIsInstance<String>()?.joinToString("\n")?.takeIf {
                                        it.contains("-----BEGIN ") && it.contains("-----END ") && it.contains(" PRIVATE KEY-----")
                                    }
                                    if (cert != null && key != null) {
                                        http3Bean.mtlsCertificate = cert
                                        http3Bean.mtlsCertificatePrivateKey = key
                                    }
                                }
                            }
                            "verify" -> {
                                if (!certificate.hasCaseInsensitive("certificateFile")) {
                                    val cert = certificate.optArray("certificate")?.filterIsInstance<String>()?.joinToString("\n")?.takeIf {
                                        it.contains("-----BEGIN ") && it.contains("-----END ") && it.contains(" CERTIFICATE-----")
                                    }
                                    if (cert != null) {
                                        http3Bean.certificates = cert
                                    }
                                }
                            }
                        }
                    }
                    tlsSettings.optArray("pinnedPeerCertificateChainSha256")?.filterIsInstance<String>()?.also {
                        http3Bean.pinnedPeerCertificateChainSha256 = it.joinToString("\n")
                        tlsSettings.optBool("allowInsecureIfPinnedPeerCertificate")?.also { allowInsecure ->
                            http3Bean.allowInsecure = allowInsecure
                        }
                    }
                    tlsSettings.optArray("pinnedPeerCertificatePublicKeySha256")?.filterIsInstance<String>()?.also {
                        http3Bean.pinnedPeerCertificatePublicKeySha256 = it.joinToString("\n")
                        tlsSettings.optBool("allowInsecureIfPinnedPeerCertificate")?.also { allowInsecure ->
                            http3Bean.allowInsecure = allowInsecure
                        }
                    }
                    tlsSettings.optArray("pinnedPeerCertificateSha256")?.filterIsInstance<String>()?.also {
                        http3Bean.pinnedPeerCertificateSha256 = it.joinToString("\n")
                        tlsSettings.optBool("allowInsecureIfPinnedPeerCertificate")?.also { allowInsecure ->
                            http3Bean.allowInsecure = allowInsecure
                        }
                    }
                }
            }
            return listOf(http3Bean)
        }
        "anytls" -> {
            outbound.optObject("streamSettings")?.also { streamSettings ->
                streamSettings.optStr("network")?.lowercase()?.also {
                    if (it in nonRawTransportName) return listOf()
                }
            }
            val anytlsBean = AnyTLSBean()
            outbound.optObject("settings")?.also { settings ->
                outbound.optStr("tag")?.also {
                    anytlsBean.name = it
                }
                settings.optStr("address")?.also {
                    anytlsBean.serverAddress = it
                } ?: return listOf()
                settings.optV2RayPort("port")?.also {
                    anytlsBean.serverPort = it
                } ?: return listOf()
                settings.optStr("password")?.also {
                    anytlsBean.password = it
                }
            }
            outbound.optObject("streamSettings")?.also { streamSettings ->
                when (val security = streamSettings.optStr("security")?.lowercase()) {
                    "tls", "utls" -> {
                        anytlsBean.security = "tls"
                        var tlsConfig = streamSettings.optObject("tlsSettings")
                        if (security == "utls") {
                            streamSettings.optObject("utlsSettings")?.also {
                                tlsConfig = it.optObject("tlsConfig")
                            }
                        }
                        tlsConfig?.also { tlsSettings ->
                            tlsSettings.optStr("serverName")?.also {
                                anytlsBean.sni = it
                            }
                            tlsSettings.optArray("alpn")?.filterIsInstance<String>()?.also {
                                anytlsBean.alpn = it.joinToString("\n")
                            } ?: tlsSettings.optStr("alpn")?.also {
                                anytlsBean.alpn = it.split(",").joinToString("\n")
                            }
                            tlsSettings.optBool("allowInsecure")?.also {
                                anytlsBean.allowInsecure = it
                            }
                            tlsSettings.optArray("certificates")?.filterIsInstance<JSONObject>()?.asReversed()?.forEach { certificate ->
                                when (certificate.optStr("usage")?.lowercase()) {
                                    null, "", "encipherment" -> {
                                        if (!certificate.hasCaseInsensitive("certificateFile") && !certificate.hasCaseInsensitive("keyFile")) {
                                            val cert = certificate.optArray("certificate")?.filterIsInstance<String>()?.joinToString("\n")?.takeIf {
                                                it.contains("-----BEGIN ") && it.contains("-----END ") && it.contains(" CERTIFICATE-----")
                                            }
                                            val key = certificate.optArray("key")?.filterIsInstance<String>()?.joinToString("\n")?.takeIf {
                                                it.contains("-----BEGIN ") && it.contains("-----END ") && it.contains(" PRIVATE KEY-----")
                                            }
                                            if (cert != null && key != null) {
                                                anytlsBean.mtlsCertificate = cert
                                                anytlsBean.mtlsCertificatePrivateKey = key
                                            }
                                        }
                                    }
                                    "verify" -> {
                                        if (!certificate.hasCaseInsensitive("certificateFile")) {
                                            val cert = certificate.optArray("certificate")?.filterIsInstance<String>()?.joinToString("\n")?.takeIf {
                                                it.contains("-----BEGIN ") && it.contains("-----END ") && it.contains(" CERTIFICATE-----")
                                            }
                                            if (cert != null) {
                                                anytlsBean.certificates = cert
                                            }
                                        }
                                    }
                                }
                            }
                            tlsSettings.optArray("pinnedPeerCertificateChainSha256")?.filterIsInstance<String>()?.also {
                                anytlsBean.pinnedPeerCertificateChainSha256 = it.joinToString("\n")
                                tlsSettings.optBool("allowInsecureIfPinnedPeerCertificate")?.also { allowInsecure ->
                                    anytlsBean.allowInsecure = allowInsecure
                                }
                            }
                            tlsSettings.optArray("pinnedPeerCertificatePublicKeySha256")?.filterIsInstance<String>()?.also {
                                anytlsBean.pinnedPeerCertificatePublicKeySha256 = it.joinToString("\n")
                                tlsSettings.optBool("allowInsecureIfPinnedPeerCertificate")?.also { allowInsecure ->
                                    anytlsBean.allowInsecure = allowInsecure
                                }
                            }
                            tlsSettings.optArray("pinnedPeerCertificateSha256")?.filterIsInstance<String>()?.also {
                                anytlsBean.pinnedPeerCertificateSha256 = it.joinToString("\n")
                                tlsSettings.optBool("allowInsecureIfPinnedPeerCertificate")?.also { allowInsecure ->
                                    anytlsBean.allowInsecure = allowInsecure
                                }
                            }
                        }
                    }
                    "reality" -> {
                        anytlsBean.security = "reality"
                        streamSettings.optObject("realitySettings")?.also { realitySettings ->
                            realitySettings.optStr("serverName")?.also {
                                anytlsBean.sni = it
                            }
                            realitySettings.optStr("publicKey")?.also {
                                anytlsBean.realityPublicKey = it
                            }
                            realitySettings.optStr("shortId")?.also {
                                anytlsBean.realityShortId = it
                            }
                        }
                    }
                    else -> anytlsBean.security = "none"
                }
            }
            return listOf(anytlsBean)
        }
        "juicity" -> {
            val juicityBean = JuicityBean()
            outbound.optObject("settings")?.also { settings ->
                outbound.optStr("tag")?.also {
                    juicityBean.name = it
                }
                settings.optStr("address")?.also {
                    juicityBean.serverAddress = it
                } ?: return listOf()
                settings.optV2RayPort("port")?.also {
                    juicityBean.serverPort = it
                } ?: return listOf()
                settings.optStr("uuid")?.also {
                    juicityBean.uuid = it
                }
                settings.optStr("password")?.also {
                    juicityBean.password = it
                }
                settings.optStr("congestionControl")?.also {
                    juicityBean.congestionControl = if (it in supportedJuicityCongestionControl) it else "bbr"
                }
                settings.optObject("tlsSettings")?.also { tlsSettings ->
                    tlsSettings.optStr("serverName")?.also {
                        juicityBean.sni = it
                    }
                    tlsSettings.optBool("allowInsecure")?.also {
                        juicityBean.allowInsecure = it
                    }
                    tlsSettings.optArray("certificates")?.filterIsInstance<JSONObject>()?.asReversed()?.forEach { certificate ->
                        when (certificate.optStr("usage")?.lowercase()) {
                            null, "", "encipherment" -> {
                                if (!certificate.hasCaseInsensitive("certificateFile") && !certificate.hasCaseInsensitive("keyFile")) {
                                    val cert = certificate.optArray("certificate")?.filterIsInstance<String>()?.joinToString("\n")?.takeIf {
                                        it.contains("-----BEGIN ") && it.contains("-----END ") && it.contains(" CERTIFICATE-----")
                                    }
                                    val key = certificate.optArray("key")?.filterIsInstance<String>()?.joinToString("\n")?.takeIf {
                                        it.contains("-----BEGIN ") && it.contains("-----END ") && it.contains(" PRIVATE KEY-----")
                                    }
                                    if (cert != null && key != null) {
                                        juicityBean.mtlsCertificate = cert
                                        juicityBean.mtlsCertificatePrivateKey = key
                                    }
                                }
                            }
                            "verify" -> {
                                if (!certificate.hasCaseInsensitive("certificateFile")) {
                                    val cert = certificate.optArray("certificate")?.filterIsInstance<String>()?.joinToString("\n")?.takeIf {
                                        it.contains("-----BEGIN ") && it.contains("-----END ") && it.contains(" CERTIFICATE-----")
                                    }
                                    if (cert != null) {
                                        juicityBean.certificates = cert
                                    }
                                }
                            }
                        }
                    }
                    tlsSettings.optArray("pinnedPeerCertificateChainSha256")?.filterIsInstance<String>()?.also {
                        juicityBean.pinnedPeerCertificateChainSha256 = it.joinToString("\n")
                        // match Juicity's behavior
                        // https://github.com/juicity/juicity/blob/412dbe43e091788c5464eb2d6e9c169bdf39f19c/cmd/client/run.go#L97
                        juicityBean.allowInsecure = true
                    }
                    tlsSettings.optArray("pinnedPeerCertificatePublicKeySha256")?.filterIsInstance<String>()?.also {
                        juicityBean.pinnedPeerCertificatePublicKeySha256 = it.joinToString("\n")
                        tlsSettings.optBool("allowInsecureIfPinnedPeerCertificate")?.also { allowInsecure ->
                            juicityBean.allowInsecure = allowInsecure
                        }
                    }
                    tlsSettings.optArray("pinnedPeerCertificateSha256")?.filterIsInstance<String>()?.also {
                        juicityBean.pinnedPeerCertificateSha256 = it.joinToString("\n")
                        tlsSettings.optBool("allowInsecureIfPinnedPeerCertificate")?.also { allowInsecure ->
                            juicityBean.allowInsecure = allowInsecure
                        }
                    }
                }
            }
            return listOf(juicityBean)
        }
        "wireguard" -> {
            val beanList = mutableListOf<WireGuardBean>()
            val wireguardBean = WireGuardBean()
            outbound.optStr("tag")?.also {
                wireguardBean.name = it
            }
            outbound.optObject("settings")?.also { settings ->
                settings.optStr("secretKey")?.also {
                    // https://github.com/XTLS/Xray-core/blob/d8934cf83946e88210b6bb95d793bc06e12b6db8/infra/conf/wireguard.go#L126-L148
                    wireguardBean.privateKey = it.replace('_', '/').replace('-', '+')
                    if (wireguardBean.privateKey.length == 43) wireguardBean.privateKey += "="
                }
                // https://github.com/XTLS/Xray-core/blob/d8934cf83946e88210b6bb95d793bc06e12b6db8/infra/conf/wireguard.go#L75
                wireguardBean.localAddress = "10.0.0.1/32\nfd59:7153:2388:b5fd:0000:0000:0000:0001/128"
                (settings.optArray("address") as? List<String>)?.also {
                    wireguardBean.localAddress = it.joinToString("\n")
                }
                wireguardBean.mtu = 1420
                settings.optInteger("mtu")?.takeIf { it > 0 }?.also {
                    wireguardBean.mtu = it
                }
                (settings.optArray("reserved") as? List<Int>)?.also {
                    if (it.size == 3) {
                        wireguardBean.reserved = listOf(it[0].toString(), it[1].toString(), it[2].toString()).joinToString(",")
                    }
                }
                settings.optArray("peers")?.filterIsInstance<JSONObject>()?.forEach { peer ->
                    beanList.add(wireguardBean.applyDefaultValues().clone().apply {
                        peer.optStr("endpoint")?.also { endpoint ->
                            serverAddress = endpoint.substringBeforeLast(":").removePrefix("[").removeSuffix("]")
                            serverPort = endpoint.substringAfterLast(":").toIntOrNull() ?: return listOf()
                        }
                        peer.optStr("publicKey")?.also {
                            peerPublicKey = it.replace('_', '/').replace('-', '+')
                            if (peerPublicKey.length == 43) peerPublicKey += "="
                        }
                        peer.optStr("preSharedKey")?.also {
                            peerPreSharedKey = it.replace('_', '/').replace('-', '+')
                            if (peerPreSharedKey.length == 43) peerPreSharedKey += "="
                        }
                        peer.optInteger("keepAlive")?.takeIf { it > 0 }?.also {
                            keepaliveInterval = it
                        }
                    })
                }
            }
            return beanList
        }
        else -> return listOf()
    }
}

private fun JSONObject.optV2RayPort(key: String): Int? {
    if (this.has(key)) {
        return when (val value = this.opt(key)) {
            is Int -> return value
            is String -> return value.toInt()
            else -> null
        }
    }
    for (it in this.keys()) {
        if (it.lowercase() == key.lowercase()) {
            return when (val value = this.opt(it)) {
                is Int -> value
                is String -> value.toInt()
                else -> null
            }
        }
    }
    return null
}
