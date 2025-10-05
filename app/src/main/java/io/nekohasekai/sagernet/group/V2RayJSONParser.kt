/******************************************************************************
 *                                                                            *
 * Copyright (C) 2023 by dyhkwong                                             *
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

import cn.hutool.core.lang.UUID
import cn.hutool.json.JSONObject
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

@Suppress("UNCHECKED_CAST")
fun parseV2RayOutbound(outbound: Map<String, Any?>): List<AbstractBean> {
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
                                (tlsSettings.getAny("alpn") as? List<String>)?.also {
                                    v2rayBean.alpn = it.joinToString("\n")
                                } ?: tlsSettings.getString("alpn")?.also {
                                    v2rayBean.alpn = it.split(",").joinToString("\n")
                                }
                                tlsSettings.getBoolean("allowInsecure")?.also {
                                    v2rayBean.allowInsecure = it
                                }
                                (tlsSettings.getAny("certificates") as? List<Map<String, Any?>>)?.asReversed()?.forEach { certificate ->
                                    when (certificate.getString("usage")?.lowercase()) {
                                        null, "", "encipherment" -> {
                                            v2rayBean.mtlsCertificate = (certificate.getAny("certificate") as? List<String>)?.joinToString("\n")
                                            v2rayBean.mtlsCertificatePrivateKey = (certificate.getAny("key") as? List<String>)?.joinToString("\n")
                                        }
                                        "verify" -> {
                                            v2rayBean.certificates = (certificate.getAny("certificate") as? List<String>)?.joinToString("\n")
                                        }
                                    }
                                }
                                (tlsSettings.getObject("pinnedPeerCertificateChainSha256") as? List<String>)?.also {
                                    v2rayBean.pinnedPeerCertificateChainSha256 = it.joinToString("\n")
                                    tlsSettings.getBoolean("allowInsecureIfPinnedPeerCertificate")?.also { allowInsecure ->
                                        v2rayBean.allowInsecure = allowInsecure
                                    }
                                }
                                (tlsSettings.getObject("pinnedPeerCertificatePublicKeySha256") as? List<String>)?.also {
                                    v2rayBean.pinnedPeerCertificatePublicKeySha256 = it.joinToString("\n")
                                    tlsSettings.getBoolean("allowInsecureIfPinnedPeerCertificate")?.also { allowInsecure ->
                                        v2rayBean.allowInsecure = allowInsecure
                                    }
                                }
                                (tlsSettings.getObject("pinnedPeerCertificateSha256") as? List<String>)?.also {
                                    v2rayBean.pinnedPeerCertificateSha256 = it.joinToString("\n")
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
                                    header.getString("type")?.lowercase()?.also { type ->
                                        when (type) {
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
                                    try {
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
                                    } catch (_: Exception) {}
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
                                var extra = JSONObject()
                                (splithttpSettings.getObject("extra") as? JSONObject)?.also {
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
                                            return listOf()
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
                            settings.getV2RayPort("port")?.also {
                                v2rayBean.serverPort = it
                            } ?: return listOf()
                            settings.getString("id")?.also {
                                v2rayBean.uuid = try {
                                    UUID.fromString(it).toString()
                                } catch (_: Exception) {
                                    uuid5(it)
                                }
                            }
                            settings.getString("security")?.lowercase()?.also {
                                if (it !in supportedVmessMethod) return listOf()
                                v2rayBean.encryption = it
                            }
                            settings.getInteger("alterId")?.also {
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
                            vnext.getV2RayPort("port")?.also {
                                v2rayBean.serverPort = it
                            } ?: return listOf()
                            vnext.getArray("users")?.get(0)?.also { user ->
                                user.getString("id")?.also {
                                    v2rayBean.uuid = try {
                                        UUID.fromString(it).toString()
                                    } catch (_: Exception) {
                                        uuid5(it)
                                    }
                                }
                                user.getString("security")?.lowercase()?.also {
                                    if (it !in supportedVmessMethod) return listOf()
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
                        settings.getString("address")?.also { address ->
                            settings.getString("reverse")?.also {
                                return listOf()
                            }
                            v2rayBean.serverAddress = address
                            settings.getV2RayPort("port")?.also {
                                v2rayBean.serverPort = it
                            } ?: return listOf()
                            settings.getString("id")?.also {
                                v2rayBean.uuid = try {
                                    UUID.fromString(it).toString()
                                } catch (_: Exception) {
                                    uuid5(it)
                                }
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
                            vnext.getV2RayPort("port")?.also {
                                v2rayBean.serverPort = it
                            } ?: return listOf()
                            vnext.getArray("users")?.get(0)?.also { user ->
                                user.getString("id")?.also {
                                    v2rayBean.uuid = try {
                                        UUID.fromString(it).toString()
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
                            settings.getV2RayPort("port")?.also {
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
                            server.getV2RayPort("port")?.also {
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
                        settings.getV2RayPort("port")?.also {
                            v2rayBean.serverPort = it
                        } ?: return listOf()
                        settings.getString("method")?.lowercase()?.also {
                            if (it !in supportedShadowsocks2022Method) return listOf()
                            v2rayBean.method = it
                        }
                        settings.getString("psk")?.also { psk ->
                            v2rayBean.password = psk
                            (settings.getAny("ipsk") as? List<String>)?.also { ipsk ->
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
                        settings.getV2RayPort("port")?.also {
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
                            settings.getV2RayPort("port")?.also {
                                v2rayBean.serverPort = it
                            } ?: return listOf()
                            settings.getString("password")?.also {
                                v2rayBean.password = it
                            }
                        } ?: settings.getArray("servers")?.get(0)?.also { server ->
                            server.getString("address")?.also {
                                v2rayBean.serverAddress = it
                            } ?: return listOf()
                            server.getV2RayPort("port")?.also {
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
                            v2rayBean.serverAddress = address
                            settings.getV2RayPort("port")?.also {
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
                            server.getV2RayPort("port")?.also {
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
                "http" -> {
                    v2rayBean as HttpBean
                    outbound.getString("tag")?.also {
                        v2rayBean.name = it
                    }
                    outbound.getObject("settings")?.also { settings ->
                        settings.getString("address")?.also { address ->
                            v2rayBean.serverAddress = address
                            settings.getV2RayPort("port")?.also {
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
                            server.getV2RayPort("port")?.also {
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
                    settings.getV2RayPort("port")?.also {
                        hysteria2Bean.serverPorts = it.toString()
                    } ?: return listOf()
                } ?: settings.getArray("servers")?.get(0)?.also { server ->
                    server.getString("address")?.also {
                        hysteria2Bean.serverAddress = it
                    } ?: return listOf()
                    server.getV2RayPort("port")?.also {
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
                                hy2Settings.getLongInteger("hopInterval")?.also {
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
                                (tlsSettings.getAny("certificates") as? List<Map<String, Any?>>)?.asReversed()?.forEach { certificate ->
                                    when (certificate.getString("usage")?.lowercase()) {
                                        null, "", "encipherment" -> {
                                            hysteria2Bean.mtlsCertificate = (certificate.getAny("certificate") as? List<String>)?.joinToString("\n")
                                            hysteria2Bean.mtlsCertificatePrivateKey = (certificate.getAny("key") as? List<String>)?.joinToString("\n")
                                        }
                                        "verify" -> {
                                            hysteria2Bean.certificates = (certificate.getAny("certificate") as? List<String>)?.joinToString("\n")
                                        }
                                    }
                                }
                                (tlsSettings.getObject("pinnedPeerCertificateChainSha256") as? List<String>)?.also {
                                    hysteria2Bean.pinnedPeerCertificateChainSha256 = it.joinToString("\n")
                                    tlsSettings.getBoolean("allowInsecureIfPinnedPeerCertificate")?.also { allowInsecure ->
                                        hysteria2Bean.allowInsecure = allowInsecure
                                    }
                                }
                                (tlsSettings.getObject("pinnedPeerCertificatePublicKeySha256") as? List<String>)?.also {
                                    hysteria2Bean.pinnedPeerCertificatePublicKeySha256 = it.joinToString("\n")
                                    tlsSettings.getBoolean("allowInsecureIfPinnedPeerCertificate")?.also { allowInsecure ->
                                        hysteria2Bean.allowInsecure = allowInsecure
                                    }
                                }
                                (tlsSettings.getObject("pinnedPeerCertificateSha256") as? List<String>)?.also {
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
                settings.getV2RayPort("port")?.also {
                    sshBean.serverPort = it
                } ?: return listOf()
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
                settings.getV2RayPort("port")?.also {
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
                settings.getV2RayPort("port")?.also {
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
                    (tlsSettings.getAny("certificates") as? List<Map<String, Any?>>)?.asReversed()?.forEach { certificate ->
                        when (certificate.getString("usage")?.lowercase()) {
                            null, "", "encipherment" -> {
                                http3Bean.mtlsCertificate = (certificate.getAny("certificate") as? List<String>)?.joinToString("\n")
                                http3Bean.mtlsCertificatePrivateKey = (certificate.getAny("key") as? List<String>)?.joinToString("\n")
                            }
                            "verify" -> {
                                http3Bean.certificates = (certificate.getAny("certificate") as? List<String>)?.joinToString("\n")
                            }
                        }
                    }
                    (tlsSettings.getObject("pinnedPeerCertificateChainSha256") as? List<String>)?.also {
                        http3Bean.pinnedPeerCertificateChainSha256 = it.joinToString("\n")
                        tlsSettings.getBoolean("allowInsecureIfPinnedPeerCertificate")?.also { allowInsecure ->
                            http3Bean.allowInsecure = allowInsecure
                        }
                    }
                    (tlsSettings.getObject("pinnedPeerCertificatePublicKeySha256") as? List<String>)?.also {
                        http3Bean.pinnedPeerCertificatePublicKeySha256 = it.joinToString("\n")
                        tlsSettings.getBoolean("allowInsecureIfPinnedPeerCertificate")?.also { allowInsecure ->
                            http3Bean.allowInsecure = allowInsecure
                        }
                    }
                    (tlsSettings.getObject("pinnedPeerCertificateSha256") as? List<String>)?.also {
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
                settings.getV2RayPort("port")?.also {
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
                            (tlsSettings.getAny("alpn") as? List<String>)?.also {
                                anytlsBean.alpn = it.joinToString("\n")
                            } ?: tlsSettings.getString("alpn")?.also {
                                anytlsBean.alpn = it.split(",").joinToString("\n")
                            }
                            tlsSettings.getBoolean("allowInsecure")?.also {
                                anytlsBean.allowInsecure = it
                            }
                            (tlsSettings.getAny("certificates") as? List<Map<String, Any?>>)?.asReversed()?.forEach { certificate ->
                                when (certificate.getString("usage")?.lowercase()) {
                                    null, "", "encipherment" -> {
                                        anytlsBean.mtlsCertificate = (certificate.getAny("certificate") as? List<String>)?.joinToString("\n")
                                        anytlsBean.mtlsCertificatePrivateKey = (certificate.getAny("key") as? List<String>)?.joinToString("\n")
                                    }
                                    "verify" -> {
                                        anytlsBean.certificates = (certificate.getAny("certificate") as? List<String>)?.joinToString("\n")
                                    }
                                }
                            }
                            (tlsSettings.getObject("pinnedPeerCertificateChainSha256") as? List<String>)?.also {
                                anytlsBean.pinnedPeerCertificateChainSha256 = it.joinToString("\n")
                                tlsSettings.getBoolean("allowInsecureIfPinnedPeerCertificate")?.also { allowInsecure ->
                                    anytlsBean.allowInsecure = allowInsecure
                                }
                            }
                            (tlsSettings.getObject("pinnedPeerCertificatePublicKeySha256") as? List<String>)?.also {
                                anytlsBean.pinnedPeerCertificatePublicKeySha256 = it.joinToString("\n")
                                tlsSettings.getBoolean("allowInsecureIfPinnedPeerCertificate")?.also { allowInsecure ->
                                    anytlsBean.allowInsecure = allowInsecure
                                }
                            }
                            (tlsSettings.getObject("pinnedPeerCertificateSha256") as? List<String>)?.also {
                                anytlsBean.pinnedPeerCertificateSha256 = it.joinToString("\n")
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
                settings.getV2RayPort("port")?.also {
                    juicityBean.serverPort = it
                } ?: return listOf()
                settings.getString("uuid")?.also {
                    juicityBean.uuid = it
                }
                settings.getString("password")?.also {
                    juicityBean.password = it
                }
                settings.getString("congestionControl")?.also {
                    juicityBean.congestionControl = if (it in supportedJuicityCongestionControl) it else "bbr"
                }
                settings.getObject("tlsSettings")?.also { tlsSettings ->
                    tlsSettings.getString("serverName")?.also {
                        juicityBean.sni = it
                    }
                    tlsSettings.getBoolean("allowInsecure")?.also {
                        juicityBean.allowInsecure = it
                    }
                    (tlsSettings.getAny("certificates") as? List<Map<String, Any?>>)?.asReversed()?.forEach { certificate ->
                        when (certificate.getString("usage")?.lowercase()) {
                            null, "", "encipherment" -> {
                                juicityBean.mtlsCertificate = (certificate.getAny("certificate") as? List<String>)?.joinToString("\n")
                                juicityBean.mtlsCertificatePrivateKey = (certificate.getAny("key") as? List<String>)?.joinToString("\n")
                            }
                            "verify" -> {
                                juicityBean.certificates = (certificate.getAny("certificate") as? List<String>)?.joinToString("\n")
                            }
                        }
                    }
                    (tlsSettings.getObject("pinnedPeerCertificateChainSha256") as? List<String>)?.also {
                        juicityBean.pinnedPeerCertificateChainSha256 = it.joinToString("\n")
                        /*tlsSettings.getBoolean("allowInsecureIfPinnedPeerCertificate")?.also { allowInsecure ->
                            juicityBean.allowInsecure = allowInsecure
                        }*/
                        // match Juicity's behavior
                        // https://github.com/juicity/juicity/blob/412dbe43e091788c5464eb2d6e9c169bdf39f19c/cmd/client/run.go#L97
                        juicityBean.allowInsecure = true
                    }
                    (tlsSettings.getObject("pinnedPeerCertificatePublicKeySha256") as? List<String>)?.also {
                        juicityBean.pinnedPeerCertificatePublicKeySha256 = it.joinToString("\n")
                        tlsSettings.getBoolean("allowInsecureIfPinnedPeerCertificate")?.also { allowInsecure ->
                            juicityBean.allowInsecure = allowInsecure
                        }
                    }
                    (tlsSettings.getObject("pinnedPeerCertificateSha256") as? List<String>)?.also {
                        juicityBean.pinnedPeerCertificateSha256 = it.joinToString("\n")
                        tlsSettings.getBoolean("allowInsecureIfPinnedPeerCertificate")?.also { allowInsecure ->
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
                        peer.getInteger("keepAlive")?.takeIf { it > 0 }?.also {
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

private fun Map<String, Any?>.getV2RayPort(key: String): Int? {
    if (this.contains(key)) {
        return when (val value = this[key]) {
            is Int -> return value
            is String -> return value.toInt()
            else -> null
        }
    }
    for (it in this) {
        if (it.key.lowercase() == key.lowercase()) {
            return when (val value = it.value) {
                is Int -> value
                is String -> value.toInt()
                else -> null
            }
        }
    }
    return null
}

private fun Map<String, Any?>.getLongInteger(key: String): Long? {
    if (this.contains(key)) {
        return when (val value = this[key]) {
            is Long -> return value
            is Int -> return value.toLong()
            else -> null
        }
    }
    for (it in this) {
        if (it.key.lowercase() == key.lowercase()) {
            return when (val value = it.value) {
                is Long -> return value
                is Int -> return value.toLong()
                else -> null
            }
        }
    }
    return null
}