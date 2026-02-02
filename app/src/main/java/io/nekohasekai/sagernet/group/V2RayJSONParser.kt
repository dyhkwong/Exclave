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
import com.google.gson.Gson
import com.google.gson.GsonBuilder
import com.google.gson.JsonArray
import com.google.gson.JsonObject
import io.nekohasekai.sagernet.fmt.AbstractBean
import io.nekohasekai.sagernet.fmt.anytls.AnyTLSBean
import io.nekohasekai.sagernet.fmt.http.HttpBean
import io.nekohasekai.sagernet.fmt.http3.Http3Bean
import io.nekohasekai.sagernet.fmt.hysteria2.Hysteria2Bean
import io.nekohasekai.sagernet.fmt.juicity.JuicityBean
import io.nekohasekai.sagernet.fmt.mieru.MieruBean
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

fun parseV2RayOutbound(outbound: JsonObject): List<AbstractBean> {
    // v2ray JSONv4 config, Xray config and JSONv4 config of Exclave's v2ray fork only
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
                                tlsSettings.getStringArray("alpn")?.also {
                                    v2rayBean.alpn = it.joinToString("\n")
                                } ?: tlsSettings.getString("alpn")?.also {
                                    v2rayBean.alpn = it.split(",").joinToString("\n")
                                }
                                tlsSettings.getBoolean("allowInsecure")?.also {
                                    v2rayBean.allowInsecure = it
                                }
                                tlsSettings.getArray("certificates")?.asReversed()?.forEach { certificate ->
                                    when (certificate.getString("usage")?.lowercase()) {
                                        null, "", "encipherment" -> {
                                            if (!certificate.contains("certificateFile") && !certificate.contains("keyFile")) {
                                                val cert = certificate.getStringArray("certificate")?.joinToString("\n")?.takeIf {
                                                    it.contains("-----BEGIN ") && it.contains("-----END ") && it.contains(" CERTIFICATE-----")
                                                }
                                                val key = certificate.getStringArray("key")?.joinToString("\n")?.takeIf {
                                                    it.contains("-----BEGIN ") && it.contains("-----END ") && it.contains(" PRIVATE KEY-----")
                                                }
                                                if (cert != null && key != null) {
                                                    v2rayBean.mtlsCertificate = cert
                                                    v2rayBean.mtlsCertificatePrivateKey = key
                                                }
                                            }
                                        }
                                        "verify" -> {
                                            if (!certificate.contains("certificateFile")) {
                                                val cert = certificate.getStringArray("certificate")?.joinToString("\n")?.takeIf {
                                                    it.contains("-----BEGIN ") && it.contains("-----END ") && it.contains(" CERTIFICATE-----")
                                                }
                                                if (cert != null) {
                                                    v2rayBean.certificates = cert
                                                }
                                            }
                                        }
                                    }
                                }
                                tlsSettings.getStringArray("pinnedPeerCertificateChainSha256")?.also {
                                    v2rayBean.pinnedPeerCertificateChainSha256 = it.joinToString("\n")
                                    tlsSettings.getBoolean("allowInsecureIfPinnedPeerCertificate")?.also { allowInsecure ->
                                        v2rayBean.allowInsecure = allowInsecure
                                    }
                                }
                                tlsSettings.getStringArray("pinnedPeerCertificatePublicKeySha256")?.also {
                                    v2rayBean.pinnedPeerCertificatePublicKeySha256 = it.joinToString("\n")
                                    tlsSettings.getBoolean("allowInsecureIfPinnedPeerCertificate")?.also { allowInsecure ->
                                        v2rayBean.allowInsecure = allowInsecure
                                    }
                                }
                                tlsSettings.getStringArray("pinnedPeerCertificateSha256")?.also {
                                    v2rayBean.pinnedPeerCertificateSha256 = it.joinToString("\n")
                                    tlsSettings.getBoolean("allowInsecureIfPinnedPeerCertificate")?.also { allowInsecure ->
                                        v2rayBean.allowInsecure = allowInsecure
                                    }
                                }
                                tlsSettings.getString("pinnedPeerCertSha256")?.takeIf { it.isNotEmpty() }?.also { pcs ->
                                    // https://github.com/XTLS/Xray-core/commit/0ca13452b8e99824e08c2c860dd0f84a4ae2859d
                                    v2rayBean.pinnedPeerCertificateSha256 =
                                        pcs.split(if (pcs.contains("~")) "~" else ",")
                                            .mapNotNull { it.trim().ifEmpty { null } }
                                            .joinToString("\n")
                                    if (!v2rayBean.pinnedPeerCertificateSha256.isNullOrEmpty()) {
                                        v2rayBean.allowInsecure = true
                                    }
                                }
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
                                    header.getString("type")?.lowercase()?.also { type ->
                                        when (type) {
                                            "none" -> {}
                                            "http" -> {
                                                v2rayBean.headerType = "http"
                                                header.getObject("request")?.also { request ->
                                                    request.getStringArray("path")?.also {
                                                        v2rayBean.path = it.joinToString("\n")
                                                    } ?: request.getString("path")?.also {
                                                        v2rayBean.path = it.split(",").joinToString("\n")
                                                    }
                                                    request.getObject("headers")?.also { headers ->
                                                        headers.getStringArray("Host")?.also {
                                                            v2rayBean.host = it.joinToString("\n")
                                                        } ?: headers.getString("Host")?.also {
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
                            streamSettings.getObject("kcpSettings")?.also { kcpSettings ->
                                kcpSettings.getString("seed")?.also {
                                    v2rayBean.mKcpSeed = it
                                }
                                kcpSettings.getObject("header")?.also { header ->
                                    header.getString("type")?.lowercase()?.also {
                                        if (it !in supportedKcpQuicHeaderType) return listOf()
                                        v2rayBean.headerType = it
                                    }
                                }
                            }
                        }
                        "ws", "websocket" -> {
                            v2rayBean.type = "ws"
                            streamSettings.getObject("wsSettings")?.also { wsSettings ->
                                wsSettings.getObject("headers")?.also {
                                    v2rayBean.host = it.getString("host")
                                }
                                wsSettings.getString("host")?.also {
                                    // Xray has a separate field of Host header
                                    // will not follow the breaking change in
                                    // https://github.com/XTLS/Xray-core/commit/a2b773135a860f63e990874c551b099dfc888471
                                    v2rayBean.host = it
                                }
                                wsSettings.getInt("maxEarlyData")?.also {
                                    v2rayBean.maxEarlyData = it
                                }
                                wsSettings.getString("earlyDataHeaderName")?.also {
                                    v2rayBean.earlyDataHeaderName = it
                                }
                                wsSettings.getString("path")?.also { path ->
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
                            streamSettings.getObject("httpSettings")?.also { httpSettings ->
                                // will not follow the breaking change in
                                // https://github.com/XTLS/Xray-core/commit/0a252ac15d34e7c23a1d3807a89bfca51cbb559b
                                httpSettings.getStringArray("host")?.also {
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
                                    if (it !in supportedQuicSecurity) return listOf()
                                    v2rayBean.quicSecurity = it
                                }
                                quicSettings.getString("key")?.also {
                                    v2rayBean.quicKey = it
                                }
                                quicSettings.getObject("header")?.also { header ->
                                    header.getString("type")?.lowercase()?.also {
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
                            (streamSettings.getObject("grpcSettings") ?: streamSettings.getObject("gunSettings"))?.also { grpcSettings ->
                                grpcSettings.getString("serviceName")?.also {
                                    v2rayBean.grpcServiceName = it
                                }
                                grpcSettings.getBoolean("multiMode")?.also {
                                    v2rayBean.grpcMultiMode = it // Xray private
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
                                    try {
                                        // RPRX's smart-assed invention. This of course will break under some conditions.
                                        val u = Libcore.parseURL(it)
                                        u.queryParameter("ed")?.also {
                                            u.deleteQueryParameter("ed")
                                            v2rayBean.path = u.string
                                        }
                                    } catch (_: Exception) {}
                                }
                                httpupgradeSettings.getInt("maxEarlyData")?.also {
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
                                            if (it !in supportedKcpQuicHeaderType) return listOf()
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
                                        else -> return listOf()
                                    }
                                }
                                // fuck RPRX `extra`
                                var extra = JsonObject()
                                splithttpSettings.getObject("extra")?.also {
                                    extra = it
                                }
                                if (!extra.contains("scMaxEachPostBytes")) {
                                    splithttpSettings.getInt("scMaxEachPostBytes")?.also {
                                        extra.addProperty("scMaxEachPostBytes", it)
                                    } ?: splithttpSettings.getString("scMaxEachPostBytes")?.also {
                                        extra.addProperty("scMaxEachPostBytes", it)
                                    }
                                }
                                if (!extra.contains("scMinPostsIntervalMs")) {
                                    splithttpSettings.getInt("scMinPostsIntervalMs")?.also {
                                        extra.addProperty("scMinPostsIntervalMs", it)
                                    } ?: splithttpSettings.getString("scMinPostsIntervalMs")?.also {
                                        extra.addProperty("scMinPostsIntervalMs", it)
                                    }
                                }
                                if (!extra.contains("xPaddingBytes")) {
                                    splithttpSettings.getInt("xPaddingBytes")?.also {
                                        extra.addProperty("xPaddingBytes", it)
                                    } ?: splithttpSettings.getString("xPaddingBytes")?.also {
                                        extra.addProperty("xPaddingBytes", it)
                                    }
                                }
                                if (!extra.contains("noGRPCHeader")) {
                                    splithttpSettings.getBoolean("noGRPCHeader")?.also {
                                        extra.addProperty("noGRPCHeader", it)
                                    }
                                }
                                if (!extra.contains("xmux")) {
                                    splithttpSettings.getObject("xmux")?.also {
                                        extra.add("xmux", it)
                                    }
                                }
                                if (!extra.contains("downloadSettings")) {
                                    splithttpSettings.getObject("downloadSettings")?.also {
                                        extra.add("downloadSettings", it)
                                    }
                                }
                                if (!extra.isEmpty) {
                                    v2rayBean.splithttpExtra = GsonBuilder().setPrettyPrinting().create().toJson(extra)
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
                    (outbound.getString("tag"))?.also {
                        v2rayBean.name = it
                    }
                    outbound.getObject("settings")?.also { settings ->
                        v2rayBean.packetEncoding = when (settings.getString("packetEncoding")?.lowercase()) {
                            "xudp" -> "xudp"
                            "packet" -> "packet"
                            else -> "none"
                        }
                        settings.getString("address")?.also { address ->
                            v2rayBean.serverAddress = address
                            settings.getPort("port")?.also {
                                v2rayBean.serverPort = it
                            } ?: return listOf()
                            settings.getString("id")?.also {
                                v2rayBean.uuid = uuidOrGenerate(it)
                            }
                            settings.getString("security")?.lowercase()?.also {
                                if (it !in supportedVmessMethod) return listOf()
                                v2rayBean.encryption = it
                            }
                            settings.getInt("alterId")?.also {
                                v2rayBean.alterId = it
                            }
                            settings.getString("experiments")?.also {
                                if (it.contains("AuthenticatedLength")) {
                                    v2rayBean.experimentalAuthenticatedLength = true
                                }
                                if (it.contains("NoTerminationSignal")) {
                                    v2rayBean.experimentalNoTerminationSignal = true
                                }
                            }
                        } ?: settings.getArray("vnext")?.get(0)?.also { vnext ->
                            vnext.getString("address")?.also {
                                v2rayBean.serverAddress = it
                            } ?: return listOf()
                            vnext.getPort("port")?.also {
                                v2rayBean.serverPort = it
                            } ?: return listOf()
                            vnext.getArray("users")?.get(0)?.also { user ->
                                user.getString("id")?.also {
                                    v2rayBean.uuid = uuidOrGenerate(it)
                                }
                                user.getString("security")?.lowercase()?.also {
                                    if (it !in supportedVmessMethod) return listOf()
                                    v2rayBean.encryption = it
                                }
                                user.getInt("alterId")?.also {
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
                        settings.getString("address")?.also { address ->
                            settings.getString("reverse")?.also {
                                return listOf()
                            }
                            v2rayBean.serverAddress = address
                            settings.getPort("port")?.also {
                                v2rayBean.serverPort = it
                            } ?: return listOf()
                            settings.getString("id")?.also {
                                v2rayBean.uuid = uuidOrGenerate(it)
                            }
                            settings.getString("flow")?.also {
                                when (it) {
                                    in supportedVlessFlow -> {
                                        v2rayBean.flow = "xtls-rprx-vision-udp443"
                                        v2rayBean.packetEncoding = "xudp"
                                    }
                                    in legacyVlessFlow,  "", "none" -> {}
                                    else -> if (it.startsWith("xtls-rprx-")) return listOf()
                                }
                            }
                            when (val encryption = settings.getString("encryption")) {
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
                        } ?: settings.getArray("vnext")?.get(0)?.also { vnext ->
                            vnext.getString("reverse")?.also {
                                return listOf()
                            }
                            vnext.getString("address")?.also {
                                v2rayBean.serverAddress = it
                            } ?: return listOf()
                            vnext.getPort("port")?.also {
                                v2rayBean.serverPort = it
                            } ?: return listOf()
                            vnext.getArray("users")?.get(0)?.also { user ->
                                user.getString("id")?.also {
                                    v2rayBean.uuid = uuidOrGenerate(it)
                                }
                                user.getString("flow")?.also {
                                    when (it) {
                                        in supportedVlessFlow -> {
                                            v2rayBean.flow = "xtls-rprx-vision-udp443"
                                            v2rayBean.packetEncoding = "xudp"
                                        }
                                        in legacyVlessFlow,  "", "none" -> {}
                                        else -> if (it.startsWith("xtls-rprx-")) return listOf()
                                    }
                                }
                                when (val encryption = user.getString("encryption")) {
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
                    outbound.getString("tag")?.also {
                        v2rayBean.name = it
                    }
                    outbound.getObject("settings")?.also { settings ->
                        settings.getString("address")?.also { address ->
                            v2rayBean.serverAddress = address
                            settings.getPort("port")?.also {
                                v2rayBean.serverPort = it
                            } ?: return listOf()
                            settings.getString("method")?.lowercase()?.also {
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
                            settings.getString("password")?.also {
                                v2rayBean.password = it
                            }
                            settings.getString("plugin")?.also { pluginId ->
                                v2rayBean.plugin = PluginOptions(pluginId, settings.getString("pluginOpts")).toString(trimId = false)
                            }
                        } ?: settings.getArray("servers")?.get(0)?.also { server ->
                            settings.getString("plugin")?.also { pluginId ->
                                v2rayBean.plugin = PluginOptions(pluginId, settings.getString("pluginOpts")).toString(trimId = false)
                            }
                            server.getString("address")?.also {
                                v2rayBean.serverAddress = it
                            } ?: return listOf()
                            server.getPort("port")?.also {
                                v2rayBean.serverPort = it
                            } ?: return listOf()
                            server.getString("method")?.lowercase()?.also {
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
                        } ?: return listOf()
                        settings.getPort("port")?.also {
                            v2rayBean.serverPort = it
                        } ?: return listOf()
                        settings.getString("method")?.lowercase()?.also {
                            if (it !in supportedShadowsocks2022Method) return listOf()
                            v2rayBean.method = it
                        }
                        settings.getString("psk")?.also { psk ->
                            v2rayBean.password = psk
                            (settings.getStringArray("ipsk"))?.also { ipsk ->
                                v2rayBean.password = ipsk.joinToString(":") + ":" + psk
                            }
                        }
                        settings.getString("plugin")?.also { pluginId ->
                            v2rayBean.plugin = PluginOptions(pluginId, settings.getString("pluginOpts")).toString(trimId = false)
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
                        } ?: return listOf()
                        settings.getPort("port")?.also {
                            v2rayBean.serverPort = it
                        } ?: return listOf()
                        settings.getString("method")?.lowercase()?.also {
                            if (it !in supportedShadowsocks2022Method) return listOf()
                            v2rayBean.method = it
                        }
                        settings.getString("password")?.also {
                            v2rayBean.password = it
                        }
                        settings.getString("plugin")?.also { pluginId ->
                            v2rayBean.plugin = PluginOptions(pluginId, settings.getString("pluginOpts")).toString(trimId = false)
                        }
                    }
                }
                "trojan" -> {
                    v2rayBean as TrojanBean
                    outbound.getString("tag")?.also {
                        v2rayBean.name = it
                    }
                    outbound.getObject("settings")?.also { settings ->
                        settings.getString("address")?.also { address ->
                            v2rayBean.serverAddress = address
                            settings.getPort("port")?.also {
                                v2rayBean.serverPort = it
                            } ?: return listOf()
                            settings.getString("password")?.also {
                                v2rayBean.password = it
                            }
                        } ?: settings.getArray("servers")?.get(0)?.also { server ->
                            server.getString("address")?.also {
                                v2rayBean.serverAddress = it
                            } ?: return listOf()
                            server.getPort("port")?.also {
                                v2rayBean.serverPort = it
                            } ?: return listOf()
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
                            else -> return listOf()
                        }
                        settings.getString("address")?.also { address ->
                            // Xray hack
                            v2rayBean.serverAddress = address
                            settings.getPort("port")?.also {
                                v2rayBean.serverPort = it
                            } ?: return listOf()
                            settings.getString("user")?.also {
                                v2rayBean.username = it
                            }
                            if (v2rayBean.protocol == SOCKSBean.PROTOCOL_SOCKS5) {
                                settings.getString("pass")?.also {
                                    v2rayBean.password = it
                                }
                            }
                        } ?: settings.getArray("servers")?.get(0)?.also { server ->
                            server.getString("address")?.also {
                                v2rayBean.serverAddress = it
                            } ?: return listOf()
                            server.getPort("port")?.also {
                                v2rayBean.serverPort = it
                            } ?: return listOf()
                            server.getArray("users")?.get(0)?.also { user ->
                                user.getString("user")?.also {
                                    v2rayBean.username = it
                                }
                                if (v2rayBean.protocol == SOCKSBean.PROTOCOL_SOCKS5) {
                                    settings.getString("pass")?.also {
                                        v2rayBean.password = it
                                    }
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
                        settings.getString("address")?.also { address ->
                            // Xray hack
                            v2rayBean.serverAddress = address
                            settings.getPort("port")?.also {
                                v2rayBean.serverPort = it
                            } ?: return listOf()
                            settings.getString("user")?.also {
                                v2rayBean.username = it
                            }
                            settings.getString("pass")?.also {
                                v2rayBean.password = it
                            }
                        } ?: settings.getArray("servers")?.get(0)?.also { server ->
                            server.getString("address")?.also {
                                v2rayBean.serverAddress = it
                            } ?: return listOf()
                            server.getPort("port")?.also {
                                v2rayBean.serverPort = it
                            } ?: return listOf()
                            server.getArray("users")?.get(0)?.also { user ->
                                user.getString("user")?.also {
                                    v2rayBean.username = it
                                }
                                user.getString("pass")?.also {
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
            outbound.getString("tag")?.also {
                hysteria2Bean.name = it
            }
            outbound.getObject("settings")?.also { settings ->
                settings.getString("address")?.also { address ->
                    hysteria2Bean.serverAddress = address
                    settings.getPort("port")?.also {
                        hysteria2Bean.serverPorts = it.toString()
                    } ?: return listOf()
                } ?: settings.getArray("servers")?.get(0)?.also { server ->
                    server.getString("address")?.also {
                        hysteria2Bean.serverAddress = it
                    } ?: return listOf()
                    server.getPort("port")?.also {
                        hysteria2Bean.serverPorts = it.toString()
                    } ?: return listOf()
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
                                hy2Settings.getLong("hopInterval")?.also {
                                    hysteria2Bean.hopInterval = it.takeIf { it > 0 }
                                }
                            }
                        }
                        else -> return listOf()
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
                                tlsSettings.getArray("certificates")?.asReversed()?.forEach { certificate ->
                                    when (certificate.getString("usage")?.lowercase()) {
                                        null, "", "encipherment" -> {
                                            if (!certificate.contains("certificateFile") && !certificate.contains("keyFile")) {
                                                val cert = certificate.getStringArray("certificate")?.joinToString("\n")?.takeIf {
                                                    it.contains("-----BEGIN ") && it.contains("-----END ") && it.contains(" CERTIFICATE-----")
                                                }
                                                val key = certificate.getStringArray("key")?.joinToString("\n")?.takeIf {
                                                    it.contains("-----BEGIN ") && it.contains("-----END ") && it.contains(" PRIVATE KEY-----")
                                                }
                                                if (cert != null && key != null) {
                                                    hysteria2Bean.mtlsCertificate = cert
                                                    hysteria2Bean.mtlsCertificatePrivateKey = key
                                                }
                                            }
                                        }
                                        "verify" -> {
                                            if (!certificate.contains("certificateFile")) {
                                                val cert = certificate.getStringArray("certificate")?.joinToString("\n")?.takeIf {
                                                    it.contains("-----BEGIN ") && it.contains("-----END ") && it.contains(" CERTIFICATE-----")
                                                }
                                                if (cert != null) {
                                                    hysteria2Bean.certificates = cert
                                                }
                                            }
                                        }
                                    }
                                }
                                tlsSettings.getStringArray("pinnedPeerCertificateChainSha256")?.also {
                                    hysteria2Bean.pinnedPeerCertificateChainSha256 = it.joinToString("\n")
                                    tlsSettings.getBoolean("allowInsecureIfPinnedPeerCertificate")?.also { allowInsecure ->
                                        hysteria2Bean.allowInsecure = allowInsecure
                                    }
                                }
                                tlsSettings.getStringArray("pinnedPeerCertificatePublicKeySha256")?.also {
                                    hysteria2Bean.pinnedPeerCertificatePublicKeySha256 = it.joinToString("\n")
                                    tlsSettings.getBoolean("allowInsecureIfPinnedPeerCertificate")?.also { allowInsecure ->
                                        hysteria2Bean.allowInsecure = allowInsecure
                                    }
                                }
                                tlsSettings.getStringArray("pinnedPeerCertificateSha256")?.also {
                                    hysteria2Bean.pinnedPeerCertificateSha256 = it.joinToString("\n")
                                    tlsSettings.getBoolean("allowInsecureIfPinnedPeerCertificate")?.also { allowInsecure ->
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
            outbound.getObject("streamSettings")?.also { streamSettings ->
                streamSettings.getString("network")?.lowercase()?.also {
                    if (it in nonRawTransportName) return listOf()
                }
                streamSettings.getString("security")?.lowercase()?.also {
                    if (it != "none") return listOf()
                }
            }
            val sshBean = SSHBean()
            outbound.getObject("settings")?.also { settings ->
                outbound.getString("tag")?.also {
                    sshBean.name = it
                }
                settings.getString("address")?.also {
                    sshBean.serverAddress = it
                } ?: return listOf()
                settings.getPort("port")?.also {
                    sshBean.serverPort = it
                } ?: return listOf()
                settings.getString("user")?.also {
                    sshBean.username = it
                }
                settings.getString("publicKey")?.also {
                    sshBean.publicKey = it
                }
                settings.getString("password")?.also {
                    sshBean.authType = SSHBean.AUTH_TYPE_PASSWORD
                    sshBean.password = it
                }
                settings.getString("privateKey")?.also {
                    sshBean.authType = SSHBean.AUTH_TYPE_PUBLIC_KEY
                    sshBean.privateKey = it
                    settings.getString("privateKeyPassphrase")?.also { privateKeyPassphrase ->
                        sshBean.privateKeyPassphrase = privateKeyPassphrase
                    }
                }
            }
            return listOf(sshBean)
        }
        "tuic" -> {
            val tuic5Bean = Tuic5Bean()
            outbound.getObject("settings")?.also { settings ->
                outbound.getString("tag")?.also {
                    tuic5Bean.name = it
                }
                settings.getString("address")?.also {
                    tuic5Bean.serverAddress = it
                } ?: return listOf()
                settings.getPort("port")?.also {
                    tuic5Bean.serverPort = it
                } ?: return listOf()
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
                    tlsSettings.getStringArray("alpn")?.also {
                        tuic5Bean.alpn = it.joinToString("\n")
                    } ?: tlsSettings.getString("alpn")?.also {
                        tuic5Bean.alpn = it.split(",").joinToString("\n")
                    }
                    tlsSettings.getArray("certificates")?.asReversed()?.forEach { certificate ->
                        when (certificate.getString("usage")?.lowercase()) {
                            null, "", "encipherment" -> {
                                if (!certificate.contains("certificateFile") && !certificate.contains("keyFile")) {
                                    val cert = certificate.getStringArray("certificate")?.joinToString("\n")?.takeIf {
                                        it.contains("-----BEGIN ") && it.contains("-----END ") && it.contains(" CERTIFICATE-----")
                                    }
                                    val key = certificate.getStringArray("key")?.joinToString("\n")?.takeIf {
                                        it.contains("-----BEGIN ") && it.contains("-----END ") && it.contains(" PRIVATE KEY-----")
                                    }
                                    if (cert != null && key != null) {
                                        tuic5Bean.mtlsCertificate = cert
                                        tuic5Bean.mtlsCertificatePrivateKey = key
                                    }
                                }
                            }
                            "verify" -> {
                                if (!certificate.contains("certificateFile")) {
                                    val cert = certificate.getStringArray("certificate")?.joinToString("\n")?.takeIf {
                                        it.contains("-----BEGIN ") && it.contains("-----END ") && it.contains(" CERTIFICATE-----")
                                    }
                                    if (cert != null) {
                                        tuic5Bean.certificates = cert
                                    }
                                }
                            }
                        }
                    }
                    tlsSettings.getStringArray("pinnedPeerCertificateChainSha256")?.also {
                        tuic5Bean.pinnedPeerCertificateChainSha256 = it.joinToString("\n")
                        tlsSettings.getBoolean("allowInsecureIfPinnedPeerCertificate")?.also { allowInsecure ->
                            tuic5Bean.allowInsecure = allowInsecure
                        }
                    }
                    tlsSettings.getStringArray("pinnedPeerCertificatePublicKeySha256")?.also {
                        tuic5Bean.pinnedPeerCertificatePublicKeySha256 = it.joinToString("\n")
                        tlsSettings.getBoolean("allowInsecureIfPinnedPeerCertificate")?.also { allowInsecure ->
                            tuic5Bean.allowInsecure = allowInsecure
                        }
                    }
                    tlsSettings.getStringArray("pinnedPeerCertificateSha256")?.also {
                        tuic5Bean.pinnedPeerCertificateSha256 = it.joinToString("\n")
                        tlsSettings.getBoolean("allowInsecureIfPinnedPeerCertificate")?.also { allowInsecure ->
                            tuic5Bean.allowInsecure = allowInsecure
                        }
                    }
                }
                settings.getBoolean("disableSNI")?.also {
                    tuic5Bean.disableSNI = it
                }
            }
            return listOf(tuic5Bean)
        }
        "http3" -> {
            val http3Bean = Http3Bean()
            outbound.getObject("settings")?.also { settings ->
                outbound.getString("tag")?.also {
                    http3Bean.name = it
                }
                settings.getString("address")?.also {
                    http3Bean.serverAddress = it
                } ?: return listOf()
                settings.getPort("port")?.also {
                    http3Bean.serverPort = it
                } ?: return listOf()
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
                    tlsSettings.getArray("certificates")?.asReversed()?.forEach { certificate ->
                        when (certificate.getString("usage")?.lowercase()) {
                            null, "", "encipherment" -> {
                                if (!certificate.contains("certificateFile") && !certificate.contains("keyFile")) {
                                    val cert = certificate.getStringArray("certificate")?.joinToString("\n")?.takeIf {
                                        it.contains("-----BEGIN ") && it.contains("-----END ") && it.contains(" CERTIFICATE-----")
                                    }
                                    val key = certificate.getStringArray("key")?.joinToString("\n")?.takeIf {
                                        it.contains("-----BEGIN ") && it.contains("-----END ") && it.contains(" PRIVATE KEY-----")
                                    }
                                    if (cert != null && key != null) {
                                        http3Bean.mtlsCertificate = cert
                                        http3Bean.mtlsCertificatePrivateKey = key
                                    }
                                }
                            }
                            "verify" -> {
                                if (!certificate.contains("certificateFile")) {
                                    val cert = certificate.getStringArray("certificate")?.joinToString("\n")?.takeIf {
                                        it.contains("-----BEGIN ") && it.contains("-----END ") && it.contains(" CERTIFICATE-----")
                                    }
                                    if (cert != null) {
                                        http3Bean.certificates = cert
                                    }
                                }
                            }
                        }
                    }
                    tlsSettings.getStringArray("pinnedPeerCertificateChainSha256")?.also {
                        http3Bean.pinnedPeerCertificateChainSha256 = it.joinToString("\n")
                        tlsSettings.getBoolean("allowInsecureIfPinnedPeerCertificate")?.also { allowInsecure ->
                            http3Bean.allowInsecure = allowInsecure
                        }
                    }
                    tlsSettings.getStringArray("pinnedPeerCertificatePublicKeySha256")?.also {
                        http3Bean.pinnedPeerCertificatePublicKeySha256 = it.joinToString("\n")
                        tlsSettings.getBoolean("allowInsecureIfPinnedPeerCertificate")?.also { allowInsecure ->
                            http3Bean.allowInsecure = allowInsecure
                        }
                    }
                    tlsSettings.getStringArray("pinnedPeerCertificateSha256")?.also {
                        http3Bean.pinnedPeerCertificateSha256 = it.joinToString("\n")
                        tlsSettings.getBoolean("allowInsecureIfPinnedPeerCertificate")?.also { allowInsecure ->
                            http3Bean.allowInsecure = allowInsecure
                        }
                    }
                }
            }
            return listOf(http3Bean)
        }
        "anytls" -> {
            outbound.getObject("streamSettings")?.also { streamSettings ->
                streamSettings.getString("network")?.lowercase()?.also {
                    if (it in nonRawTransportName) return listOf()
                }
            }
            val anytlsBean = AnyTLSBean()
            outbound.getObject("settings")?.also { settings ->
                outbound.getString("tag")?.also {
                    anytlsBean.name = it
                }
                settings.getString("address")?.also {
                    anytlsBean.serverAddress = it
                } ?: return listOf()
                settings.getPort("port")?.also {
                    anytlsBean.serverPort = it
                } ?: return listOf()
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
                            tlsSettings.getStringArray("alpn")?.also {
                                anytlsBean.alpn = it.joinToString("\n")
                            } ?: tlsSettings.getString("alpn")?.also {
                                anytlsBean.alpn = it.split(",").joinToString("\n")
                            }
                            tlsSettings.getBoolean("allowInsecure")?.also {
                                anytlsBean.allowInsecure = it
                            }
                            tlsSettings.getArray("certificates")?.asReversed()?.forEach { certificate ->
                                when (certificate.getString("usage")?.lowercase()) {
                                    null, "", "encipherment" -> {
                                        if (!certificate.contains("certificateFile") && !certificate.contains("keyFile")) {
                                            val cert = certificate.getStringArray("certificate")?.joinToString("\n")?.takeIf {
                                                it.contains("-----BEGIN ") && it.contains("-----END ") && it.contains(" CERTIFICATE-----")
                                            }
                                            val key = certificate.getStringArray("key")?.joinToString("\n")?.takeIf {
                                                it.contains("-----BEGIN ") && it.contains("-----END ") && it.contains(" PRIVATE KEY-----")
                                            }
                                            if (cert != null && key != null) {
                                                anytlsBean.mtlsCertificate = cert
                                                anytlsBean.mtlsCertificatePrivateKey = key
                                            }
                                        }
                                    }
                                    "verify" -> {
                                        if (!certificate.contains("certificateFile")) {
                                            val cert = certificate.getStringArray("certificate")?.joinToString("\n")?.takeIf {
                                                it.contains("-----BEGIN ") && it.contains("-----END ") && it.contains(" CERTIFICATE-----")
                                            }
                                            if (cert != null) {
                                                anytlsBean.certificates = cert
                                            }
                                        }
                                    }
                                }
                            }
                            tlsSettings.getStringArray("pinnedPeerCertificateChainSha256")?.also {
                                anytlsBean.pinnedPeerCertificateChainSha256 = it.joinToString("\n")
                                tlsSettings.getBoolean("allowInsecureIfPinnedPeerCertificate")?.also { allowInsecure ->
                                    anytlsBean.allowInsecure = allowInsecure
                                }
                            }
                            tlsSettings.getStringArray("pinnedPeerCertificatePublicKeySha256")?.also {
                                anytlsBean.pinnedPeerCertificatePublicKeySha256 = it.joinToString("\n")
                                tlsSettings.getBoolean("allowInsecureIfPinnedPeerCertificate")?.also { allowInsecure ->
                                    anytlsBean.allowInsecure = allowInsecure
                                }
                            }
                            tlsSettings.getStringArray("pinnedPeerCertificateSha256")?.also {
                                anytlsBean.pinnedPeerCertificateSha256 = it.joinToString("\n")
                                tlsSettings.getBoolean("allowInsecureIfPinnedPeerCertificate")?.also { allowInsecure ->
                                    anytlsBean.allowInsecure = allowInsecure
                                }
                            }
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
                        }
                    }
                    else -> anytlsBean.security = "none"
                }
            }
            return listOf(anytlsBean)
        }
        "juicity" -> {
            val juicityBean = JuicityBean()
            outbound.getObject("settings")?.also { settings ->
                outbound.getString("tag")?.also {
                    juicityBean.name = it
                }
                settings.getString("address")?.also {
                    juicityBean.serverAddress = it
                } ?: return listOf()
                settings.getPort("port")?.also {
                    juicityBean.serverPort = it
                } ?: return listOf()
                settings.getString("uuid")?.also {
                    juicityBean.uuid = it
                }
                settings.getString("password")?.also {
                    juicityBean.password = it
                }
                settings.getObject("tlsSettings")?.also { tlsSettings ->
                    tlsSettings.getString("serverName")?.also {
                        juicityBean.sni = it
                    }
                    tlsSettings.getBoolean("allowInsecure")?.also {
                        juicityBean.allowInsecure = it
                    }
                    tlsSettings.getArray("certificates")?.asReversed()?.forEach { certificate ->
                        when (certificate.getString("usage")?.lowercase()) {
                            null, "", "encipherment" -> {
                                if (!certificate.contains("certificateFile") && !certificate.contains("keyFile")) {
                                    val cert = certificate.getStringArray("certificate")?.joinToString("\n")?.takeIf {
                                        it.contains("-----BEGIN ") && it.contains("-----END ") && it.contains(" CERTIFICATE-----")
                                    }
                                    val key = certificate.getStringArray("key")?.joinToString("\n")?.takeIf {
                                        it.contains("-----BEGIN ") && it.contains("-----END ") && it.contains(" PRIVATE KEY-----")
                                    }
                                    if (cert != null && key != null) {
                                        juicityBean.mtlsCertificate = cert
                                        juicityBean.mtlsCertificatePrivateKey = key
                                    }
                                }
                            }
                            "verify" -> {
                                if (!certificate.contains("certificateFile")) {
                                    val cert = certificate.getStringArray("certificate")?.joinToString("\n")?.takeIf {
                                        it.contains("-----BEGIN ") && it.contains("-----END ") && it.contains(" CERTIFICATE-----")
                                    }
                                    if (cert != null) {
                                        juicityBean.certificates = cert
                                    }
                                }
                            }
                        }
                    }
                    tlsSettings.getStringArray("pinnedPeerCertificateChainSha256")?.also {
                        juicityBean.pinnedPeerCertificateChainSha256 = it.joinToString("\n")
                        // match Juicity's behavior
                        // https://github.com/juicity/juicity/blob/412dbe43e091788c5464eb2d6e9c169bdf39f19c/cmd/client/run.go#L97
                        juicityBean.allowInsecure = true
                    }
                    tlsSettings.getStringArray("pinnedPeerCertificatePublicKeySha256")?.also {
                        juicityBean.pinnedPeerCertificatePublicKeySha256 = it.joinToString("\n")
                        tlsSettings.getBoolean("allowInsecureIfPinnedPeerCertificate")?.also { allowInsecure ->
                            juicityBean.allowInsecure = allowInsecure
                        }
                    }
                    tlsSettings.getStringArray("pinnedPeerCertificateSha256")?.also {
                        juicityBean.pinnedPeerCertificateSha256 = it.joinToString("\n")
                        tlsSettings.getBoolean("allowInsecureIfPinnedPeerCertificate")?.also { allowInsecure ->
                            juicityBean.allowInsecure = allowInsecure
                        }
                    }
                }
            }
            return listOf(juicityBean)
        }
        "mieru" -> {
            val mieruBean = MieruBean()
            outbound.getObject("settings")?.also { settings ->
                outbound.getString("tag")?.also {
                    mieruBean.name = it
                }
                settings.getString("address")?.also {
                    mieruBean.serverAddress = it
                } ?: return listOf()
                settings.getPort("port")?.also {
                    mieruBean.serverPort = it
                }
                settings.getStringArray("portRange")?.also {
                    mieruBean.portRange = it.joinToString("\n")
                }
                if (mieruBean.serverPort == null && mieruBean.portRange == null) {
                    return listOf()
                }
                settings.getString("username")?.also {
                    mieruBean.username = it
                }
                settings.getString("password")?.also {
                    mieruBean.password = it
                }
                settings.getString("protocol")?.also {
                    mieruBean.protocol = when (it) {
                        "tcp", "" -> MieruBean.PROTOCOL_TCP
                        "udp" -> MieruBean.PROTOCOL_UDP
                        else -> return listOf()
                    }
                }
                settings.getString("multiplex")?.also {
                    mieruBean.multiplexingLevel = when (it) {
                        "off" -> MieruBean.MULTIPLEXING_OFF
                        "low" -> MieruBean.MULTIPLEXING_LOW
                        "middle" -> MieruBean.MULTIPLEXING_MIDDLE
                        "high" -> MieruBean.MULTIPLEXING_HIGH
                        else -> MieruBean.MULTIPLEXING_DEFAULT
                    }
                }
                settings.getString("handshakeMode")?.also {
                    mieruBean.handshakeMode = when (it) {
                        "standard" -> MieruBean.HANDSHAKE_STANDARD
                        "nowait" -> MieruBean.HANDSHAKE_NO_WAIT
                        else -> MieruBean.HANDSHAKE_DEFAULT
                    }
                }
            }
            return listOf(mieruBean)
        }
        "wireguard" -> {
            val beanList = mutableListOf<WireGuardBean>()
            val wireguardBean = WireGuardBean()
            outbound.getString("tag")?.also {
                wireguardBean.name = it
            }
            outbound.getObject("settings")?.also { settings ->
                settings.getString("secretKey")?.also {
                    // https://github.com/XTLS/Xray-core/blob/d8934cf83946e88210b6bb95d793bc06e12b6db8/infra/conf/wireguard.go#L126-L148
                    wireguardBean.privateKey = it.replace('_', '/').replace('-', '+')
                    if (wireguardBean.privateKey.length == 43) wireguardBean.privateKey += "="
                }
                // https://github.com/XTLS/Xray-core/blob/d8934cf83946e88210b6bb95d793bc06e12b6db8/infra/conf/wireguard.go#L75
                wireguardBean.localAddress = "10.0.0.1/32\nfd59:7153:2388:b5fd:0000:0000:0000:0001/128"
                settings.getStringArray("address")?.also {
                    wireguardBean.localAddress = it.joinToString("\n")
                }
                wireguardBean.mtu = 1420
                settings.getInt("mtu")?.takeIf { it > 0 }?.also {
                    wireguardBean.mtu = it
                }
                settings.getIntArray("reserved")?.also {
                    if (it.size == 3) {
                        wireguardBean.reserved = listOf(it[0].toString(), it[1].toString(), it[2].toString()).joinToString(",")
                    }
                }
                settings.getArray("peers")?.forEach { peer ->
                    beanList.add(wireguardBean.applyDefaultValues().clone().apply {
                        peer.getString("endpoint")?.also { endpoint ->
                            serverAddress = endpoint.substringBeforeLast(":").removePrefix("[").removeSuffix("]")
                            serverPort = endpoint.substringAfterLast(":").toIntOrNull() ?: return listOf()
                        }
                        peer.getString("publicKey")?.also {
                            peerPublicKey = it.replace('_', '/').replace('-', '+')
                            if (peerPublicKey.length == 43) peerPublicKey += "="
                        }
                        peer.getString("preSharedKey")?.also {
                            peerPreSharedKey = it.replace('_', '/').replace('-', '+')
                            if (peerPreSharedKey.length == 43) peerPreSharedKey += "="
                        }
                        peer.getInt("keepAlive")?.takeIf { it > 0 }?.also {
                            keepaliveInterval = it
                        }
                    })
                }
            }
            return beanList
        }
        "hysteria" -> {
            // Xray Hysteria 2
            val hysteria2Bean = Hysteria2Bean()
            outbound.getString("tag")?.also {
                hysteria2Bean.name = it
            }
            outbound.getObject("settings")?.also { settings ->
                when (settings.getInt("version")) {
                    2 -> {}
                    null, 0 -> {} // xray 26.1.13
                    else -> return listOf()
                }
                settings.getString("address")?.also {
                    hysteria2Bean.serverAddress = it
                }
                settings.getPort("port")?.also {
                    hysteria2Bean.serverPorts = it.toString()
                } ?: return listOf()
            }
            outbound.getObject("streamSettings")?.also { streamSettings ->
                streamSettings.getString("network")?.lowercase()?.also { network ->
                    when (network) {
                        "hysteria" -> {
                            streamSettings.getObject("hysteriaSettings")?.also { hysteriaSettings ->
                                if (hysteriaSettings.getInt("version") != 2) {
                                    return listOf()
                                }
                                hysteriaSettings.getString("auth")?.also {
                                    hysteria2Bean.auth = it
                                }
                                hysteriaSettings.getObject("udphop")?.also { udphop ->
                                    udphop.getInt("port")?.also {
                                        if (it > 0) hysteria2Bean.serverPorts = it.toString()
                                    } ?: udphop.getString("port")?.takeIf { it.isNotEmpty() }?.also {
                                        // invalid port is ignored
                                        hysteria2Bean.serverPorts = (it.split(",").joinToString(",") { it.trim() })
                                            .takeIf { it.isValidHysteriaPort(disallowFromGreaterThanTo = true) }
                                    }
                                    udphop.getLong("interval")?.also {
                                        hysteria2Bean.hopInterval = it.takeIf { it > 0 }
                                    }
                                }
                            }
                        }
                        else -> return listOf()
                    }
                }
                streamSettings.getArray("udpmasks")?.takeIf { it.isNotEmpty() }?.also { udpmasks ->
                    if (udpmasks.size != 1) return listOf() // WTF is this
                    val udpmask = udpmasks[0]
                    if (udpmask.getString("type") != "salamander") return listOf()
                    udpmask.getObject("settings")?.also { settings ->
                        settings.getString("password")?.also {
                            hysteria2Bean.obfs = it
                        }
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
                                tlsSettings.getArray("certificates")?.asReversed()?.forEach { certificate ->
                                    when (certificate.getString("usage")?.lowercase()) {
                                        null, "", "encipherment" -> {
                                            if (!certificate.contains("certificateFile") && !certificate.contains("keyFile")) {
                                                val cert = certificate.getStringArray("certificate")?.joinToString("\n")?.takeIf {
                                                    it.contains("-----BEGIN ") && it.contains("-----END ") && it.contains(" CERTIFICATE-----")
                                                }
                                                val key = certificate.getStringArray("key")?.joinToString("\n")?.takeIf {
                                                    it.contains("-----BEGIN ") && it.contains("-----END ") && it.contains(" PRIVATE KEY-----")
                                                }
                                                if (cert != null && key != null) {
                                                    hysteria2Bean.mtlsCertificate = cert
                                                    hysteria2Bean.mtlsCertificatePrivateKey = key
                                                }
                                            }
                                        }
                                        "verify" -> {
                                            if (!certificate.contains("certificateFile")) {
                                                val cert = certificate.getStringArray("certificate")?.joinToString("\n")?.takeIf {
                                                    it.contains("-----BEGIN ") && it.contains("-----END ") && it.contains(" CERTIFICATE-----")
                                                }
                                                if (cert != null) {
                                                    hysteria2Bean.certificates = cert
                                                }
                                            }
                                        }
                                    }
                                }
                                tlsSettings.getString("pinnedPeerCertSha256")?.takeIf { it.isNotEmpty() }?.also { pcs ->
                                    hysteria2Bean.pinnedPeerCertificateSha256 =
                                        pcs.split(if (pcs.contains("~")) "~" else ",")
                                            .mapNotNull { it.trim().ifEmpty { null } }
                                            .joinToString("\n")
                                    if (!hysteria2Bean.pinnedPeerCertificateSha256.isNullOrEmpty()) {
                                        hysteria2Bean.allowInsecure = true
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
        else -> return listOf()
    }
}

private fun JsonObject.contains(key: String, ignoreCase: Boolean = true): Boolean {
    val value = get(key)
    when {
        value == null -> if (!ignoreCase) return false
        value.isJsonNull -> if (!ignoreCase) return false
        else -> return true
    }
    for ((k, v) in entrySet()) {
        if (k.equals(key, ignoreCase = true) && !v.isJsonNull) {
            return true
        }
    }
    return false
}

private fun JsonObject.getString(key: String, ignoreCase: Boolean = true): String? {
    val value = get(key)
    when {
        value == null -> if (!ignoreCase) return null
        value.isJsonNull -> if (!ignoreCase) return null
        value.isJsonPrimitive -> return if (value.asJsonPrimitive.isString) value.asString else null
        else -> return null
    }
    for ((k, v) in entrySet()) {
        if (k.equals(key, ignoreCase = true) && v.isJsonPrimitive && v.asJsonPrimitive.isString) {
            return v.asString
        }
    }
    return null
}

private fun JsonObject.getInt(key: String, ignoreCase: Boolean = true): Int? {
    val value = get(key)
    when {
        value == null -> if (!ignoreCase) return null
        value.isJsonNull -> if (!ignoreCase) return null
        value.isJsonPrimitive -> {
            return if (value.asJsonPrimitive.isNumber) {
                try {
                    value.asInt
                } catch (_: Exception) {
                    null
                }
            } else {
                null
            }
        }
    }
    for ((k, v) in entrySet()) {
        if (k.equals(key, ignoreCase = true) && v.isJsonPrimitive && v.asJsonPrimitive.isNumber) {
            try {
                return v.asInt
            } catch (_: Exception) {}
        }
    }
    return null
}

private fun JsonObject.getBoolean(key: String, ignoreCase: Boolean = true): Boolean? {
    val value = get(key)
    when {
        value == null -> if (!ignoreCase) return null
        value.isJsonNull -> if (!ignoreCase) return null
        value.isJsonPrimitive -> return if (value.asJsonPrimitive.isBoolean) value.asBoolean else null
        else -> return null
    }
    for ((k, v) in entrySet()) {
        if (k.equals(key, ignoreCase = true) && v.isJsonPrimitive && v.asJsonPrimitive.isBoolean) {
            return v.asBoolean
        }
    }
    return null
}

private fun JsonObject.getLong(key: String, ignoreCase: Boolean = true): Long? {
    val value = get(key)
    when {
        value == null -> if (!ignoreCase) return null
        value.isJsonNull -> if (!ignoreCase) return null
        value.isJsonPrimitive -> {
            return if (value.asJsonPrimitive.isNumber) {
                try {
                    value.asLong
                } catch (_: Exception) {
                    null
                }
            } else {
                null
            }
        }
    }
    for ((k, v) in entrySet()) {
        if (k.equals(key, ignoreCase = true) && v.isJsonPrimitive && v.asJsonPrimitive.isNumber) {
            try {
                return v.asLong
            } catch (_: Exception) {}
        }
    }
    return null
}

private fun JsonObject.getObject(key: String, ignoreCase: Boolean = true): JsonObject? {
    val value = get(key)
    when {
        value == null -> if (!ignoreCase) return null
        value.isJsonNull -> if (!ignoreCase) return null
        value.isJsonObject -> return value.asJsonObject
        else -> return null
    }
    for ((k, v) in entrySet()) {
        if (k.equals(key, ignoreCase = true) && v.isJsonObject) {
            return v.asJsonObject
        }
    }
    return null
}

private fun JsonObject.getJsonArray(key: String, ignoreCase: Boolean = true): JsonArray? {
    val value = get(key)
    when {
        value == null -> if (!ignoreCase) return null
        value.isJsonNull -> if (!ignoreCase) return null
        value.isJsonArray -> return value.asJsonArray
        else -> return null
    }
    for ((k, v) in entrySet()) {
        if (k.equals(key, ignoreCase = true) && v.isJsonArray) {
            return v.asJsonArray
        }
    }
    return null
}

private fun JsonObject.getArray(key: String, ignoreCase: Boolean = true): List<JsonObject>? {
    val jsonArray = getJsonArray(key, ignoreCase) ?: return null
    return try {
        Gson().fromJson(jsonArray, Array<JsonObject>::class.java)?.asList()
    } catch (_: Exception) {
        null
    }
}

private fun JsonObject.getStringArray(key: String, ignoreCase: Boolean = true): List<String>? {
    val jsonArray = getJsonArray(key, ignoreCase) ?: return null
    return try {
        Gson().fromJson(jsonArray, Array<String>::class.java)?.asList()
    } catch (_: Exception) {
        null
    }
}

private fun JsonObject.getIntArray(key: String, ignoreCase: Boolean = true): List<Int>? {
    val jsonArray = getJsonArray(key, ignoreCase) ?: return null
    return try {
        Gson().fromJson(jsonArray, Array<Int>::class.java)?.asList()
    } catch (_: Exception) {
        null
    }
}

private fun JsonObject.getPort(key: String): Int? {
    val value = get(key)
    when {
        value == null -> {}
        value.isJsonNull -> {}
        value.isJsonPrimitive && value.asJsonPrimitive.isNumber -> {
            return try {
                value.asInt
            } catch (_: Exception) {
                null
            }
        }
        value.isJsonPrimitive && value.asJsonPrimitive.isString -> return value.asString.toIntOrNull()
        else -> return null
    }
    for ((k, v) in entrySet()) {
        if (k.equals(key, ignoreCase = true) && v.isJsonPrimitive) {
            when {
                v.asJsonPrimitive.isNumber -> {
                    try {
                        return v.asInt
                    } catch (_: Exception) {}
                }
                v.asJsonPrimitive.isString -> return v.asString.toIntOrNull()
            }
        }
    }
    return null
}
