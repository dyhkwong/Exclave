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

import com.google.gson.JsonObject
import io.nekohasekai.sagernet.fmt.AbstractBean
import io.nekohasekai.sagernet.fmt.http.HttpBean
import io.nekohasekai.sagernet.fmt.hysteria2.Hysteria2Bean
import io.nekohasekai.sagernet.fmt.shadowsocks.ShadowsocksBean
import io.nekohasekai.sagernet.fmt.shadowsocks.supportedShadowsocks2022Method
import io.nekohasekai.sagernet.fmt.shadowsocks.supportedShadowsocksMethod
import io.nekohasekai.sagernet.fmt.socks.SOCKSBean
import io.nekohasekai.sagernet.fmt.trojan.TrojanBean
import io.nekohasekai.sagernet.fmt.v2ray.VLESSBean
import io.nekohasekai.sagernet.fmt.v2ray.VMessBean
import io.nekohasekai.sagernet.fmt.v2ray.supportedQuicSecurity
import io.nekohasekai.sagernet.ktx.*
import kotlin.io.encoding.Base64

fun parseV2Ray5Outbound(outbound: JsonObject): List<AbstractBean> {
    when (val type = outbound.getString("protocol")) {
        "shadowsocks", "trojan", "vmess", "vless", "socks", "http", "shadowsocks2022" -> {
            val v2rayBean = when (type) {
                "shadowsocks", "shadowsocks2022" -> ShadowsocksBean()
                "trojan" -> TrojanBean()
                "vmess" -> VMessBean()
                "vless" -> VLESSBean()
                "socks" -> SOCKSBean()
                "http" -> HttpBean()
                else -> return listOf()
            }.apply {
                outbound.getString("tag")?.also {
                    name = it
                }
            }
            outbound.getObject("streamSettings")?.also { streamSettings ->
                if (streamSettings.contains("network", ignoreCase = true) || streamSettings.contains("tlsSettings", ignoreCase = true)
                    || streamSettings.contains("xtlsSettings", ignoreCase = true) || streamSettings.contains("utlsSettings", ignoreCase = true)
                    || streamSettings.contains("tcpSettings", ignoreCase = true) || streamSettings.contains("kcpSettings", ignoreCase = true)
                    || streamSettings.contains("wsSettings", ignoreCase = true) || streamSettings.contains("httpSettings", ignoreCase = true)
                    || streamSettings.contains("grpcSettings", ignoreCase = true) || streamSettings.contains("gunSettings", ignoreCase = true)
                    || streamSettings.contains("quicSettings", ignoreCase = true) || streamSettings.contains("hy2Settings", ignoreCase = true)
                    || streamSettings.contains("rawSettings", ignoreCase = true) || streamSettings.contains("splithttpSettings", ignoreCase = true)
                    || streamSettings.contains("xhttpSettings", ignoreCase = true)
                ) { // jsonv4
                    return listOf()
                }
                streamSettings.getString("security")?.also { security ->
                    when (security) {
                        "none", "" -> {}
                        "tls", "utls" -> {
                            v2rayBean.security = "tls"
                            val securitySettings = streamSettings.getObject("securitySettings")
                            val tls = if (security == "tls") {
                                securitySettings
                            } else {
                                securitySettings?.getObject("tlsConfig")
                                    ?: securitySettings?.getObject("tls_config")
                            }
                            tls?.also { tlsConfig ->
                                (tlsConfig.getString("serverName") ?: tlsConfig.getString("server_name"))?.also {
                                    v2rayBean.sni = it
                                }
                                tlsConfig.getStringArray("nextProtocol")?.also {
                                    v2rayBean.alpn = it.joinToString("\n")
                                } ?: tlsConfig.getStringArray("next_protocol")?.also {
                                    v2rayBean.alpn = it.joinToString("\n")
                                }
                                tlsConfig.getArray("certificate")?.asReversed()?.forEach { certificate ->
                                    when (certificate.getString("usage")) {
                                        null, "ENCIPHERMENT" -> {
                                            if (!certificate.has("certificateFile") && !certificate.has("certificate_file")
                                                && !certificate.has("keyFile") && !certificate.has("key_file")) {
                                                val cert = certificate.getString("Certificate")
                                                val key = certificate.getString("Key")
                                                if (cert != null && key != null) {
                                                    try {
                                                        v2rayBean.mtlsCertificate = String(Base64.decode(cert)).takeIf {
                                                            it.contains("-----BEGIN ") && it.contains("-----END ") && it.contains(" CERTIFICATE-----")
                                                        }
                                                        v2rayBean.mtlsCertificatePrivateKey = String(Base64.decode(key)).takeIf {
                                                            it.contains("-----BEGIN ") && it.contains("-----END ") && it.contains(" PRIVATE KEY-----")
                                                        }
                                                    } catch (_: Exception) {}
                                                }
                                            }
                                        }
                                        "AUTHORITY_VERIFY" -> {
                                            if (!certificate.has("certificateFile") && !certificate.has("certificate_file")) {
                                                val cert = certificate.getString("Certificate")
                                                if (cert != null) {
                                                    try {
                                                        v2rayBean.certificates = String(Base64.decode(cert)).takeIf {
                                                            it.contains("-----BEGIN ") && it.contains("-----END ") && it.contains(" CERTIFICATE-----")
                                                        }
                                                    } catch (_: Exception) {}
                                                }
                                            }
                                        }
                                    }
                                }
                                (tlsConfig.getStringArray("pinnedPeerCertificateChainSha256")
                                    ?: tlsConfig.getStringArray("pinned_peer_certificate_chain_sha256"))?.also {
                                    v2rayBean.pinnedPeerCertificateChainSha256 = it.joinToString("\n")
                                    (tlsConfig.getBoolean("allowInsecureIfPinnedPeerCertificate")
                                        ?: tlsConfig.getBoolean("allow_insecure_if_pinned_peer_certificate"))?.also { allowInsecure ->
                                        v2rayBean.allowInsecure = allowInsecure
                                    }
                                }
                            }
                        }
                        else -> return listOf()
                    }
                }
                streamSettings.getString("transport")?.also { transport ->
                    when (transport) {
                        "tcp", "" -> {
                            v2rayBean.type = "tcp"
                            streamSettings.getObject("transportSettings")?.also { transportSettings ->
                                (transportSettings.getObject("headerSettings")
                                    ?: transportSettings.getObject("header_settings"))?.also { headerSettings ->
                                        when (headerSettings.getString("@type")) {
                                            "v2ray.core.transport.internet.headers.http.Config" -> {
                                                v2rayBean.headerType = "http"
                                                headerSettings.getObject("request")?.also { request ->
                                                    request.getStringArray("uri")?.also {
                                                        v2rayBean.path = it.joinToString("\n")
                                                    }
                                                    request.getArray("header")?.forEach {
                                                        if (it.getString("name")?.lowercase() == "host") {
                                                            v2rayBean.host = it.getStringArray("value")?.joinToString("\n")
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
                                transportSettings.getString("seed")?.also {
                                    v2rayBean.mKcpSeed = it
                                }
                                (transportSettings.getObject("headerConfig")
                                    ?: transportSettings.getObject("header_config"))?.also { headerConfig ->
                                    when (headerConfig.getString("@type")) {
                                        null, "types.v2fly.org/v2ray.core.transport.internet.headers.noop.Config",
                                        "types.v2fly.org/v2ray.core.transport.internet.headers.noop.ConnectionConfig" -> v2rayBean.headerType = "none"
                                        "types.v2fly.org/v2ray.core.transport.internet.headers.srtp.Config" -> v2rayBean.headerType = "srtp"
                                        "types.v2fly.org/v2ray.core.transport.internet.headers.utp.Config" -> v2rayBean.headerType = "utp"
                                        "types.v2fly.org/v2ray.core.transport.internet.headers.wechat.VideoConfig" -> v2rayBean.headerType = "wechat-video"
                                        "types.v2fly.org/v2ray.core.transport.internet.headers.tls.PacketConfig" -> v2rayBean.headerType = "dtls"
                                        "types.v2fly.org/v2ray.core.transport.internet.headers.wireguard.WireguardConfig" -> v2rayBean.headerType = "wireguard"
                                        else -> return listOf()
                                    }
                                }
                            }
                        }
                        "ws" -> {
                            v2rayBean.type = "ws"
                            streamSettings.getObject("transportSettings")?.also { transportSettings ->
                                transportSettings.getString("path")?.also {
                                    v2rayBean.path = it
                                }
                                (transportSettings.getInt("maxEarlyData")
                                    ?: transportSettings.getInt("max_early_data"))?.also {
                                    v2rayBean.maxEarlyData = it
                                }
                                (transportSettings.getString("earlyDataHeaderName")
                                    ?: transportSettings.getString("early_data_header_name"))?.also {
                                    v2rayBean.earlyDataHeaderName = it
                                }
                                transportSettings.getArray("header")?.forEach {
                                    if (it.getString("key")?.lowercase() == "host") {
                                        v2rayBean.host = it.getStringArray("value")?.joinToString("\n")
                                    }
                                }
                            }
                        }
                        "h2" -> {
                            v2rayBean.type = "http"
                            streamSettings.getObject("transportSettings")?.also { transportSettings ->
                                transportSettings.getString("path")?.also {
                                    v2rayBean.path = it
                                }
                                transportSettings.getStringArray("host")?.also {
                                    v2rayBean.host = it.joinToString("\n")
                                }
                            }
                        }
                        "quic" -> {
                            v2rayBean.type = "quic"
                            streamSettings.getObject("transportSettings")?.also { transportSettings ->
                                transportSettings.getString("security")?.lowercase()?.also {
                                    if (it !in supportedQuicSecurity) return listOf()
                                    v2rayBean.quicSecurity = it
                                }
                                transportSettings.getString("key")?.also {
                                    v2rayBean.quicKey = it
                                }
                                (transportSettings.getObject("headerConfig")
                                    ?: transportSettings.getObject("header_config"))?.also { headerConfig ->
                                    when (headerConfig.getString("@type")) {
                                        null, "types.v2fly.org/v2ray.core.transport.internet.headers.noop.Config",
                                        "types.v2fly.org/v2ray.core.transport.internet.headers.noop.ConnectionConfig" -> v2rayBean.headerType = "none"
                                        "types.v2fly.org/v2ray.core.transport.internet.headers.srtp.Config" -> v2rayBean.headerType = "srtp"
                                        "types.v2fly.org/v2ray.core.transport.internet.headers.utp.Config" -> v2rayBean.headerType = "utp"
                                        "types.v2fly.org/v2ray.core.transport.internet.headers.wechat.VideoConfig" -> v2rayBean.headerType = "wechat-video"
                                        "types.v2fly.org/v2ray.core.transport.internet.headers.tls.PacketConfig" -> v2rayBean.headerType = "dtls"
                                        "types.v2fly.org/v2ray.core.transport.internet.headers.wireguard.WireguardConfig" -> v2rayBean.headerType = "wireguard"
                                        else -> return listOf()
                                    }
                                }
                            }
                        }
                        "grpc" -> {
                            v2rayBean.type = "grpc"
                            streamSettings.getObject("transportSettings")?.also { transportSettings ->
                                (transportSettings.getString("serviceName")
                                    ?: transportSettings.getString("service_name"))?.also {
                                    v2rayBean.grpcServiceName = it
                                }
                            }
                        }
                        "httpupgrade" -> {
                            v2rayBean.type = "httpupgrade"
                            streamSettings.getObject("transportSettings")?.also { transportSettings ->
                                transportSettings.getString("path")?.also {
                                    v2rayBean.path = it
                                }
                                transportSettings.getString("host")?.also {
                                    v2rayBean.host = it
                                }
                                (transportSettings.getInt("maxEarlyData")
                                    ?: transportSettings.getInt("max_early_data"))?.also {
                                    v2rayBean.maxEarlyData = it
                                }
                                (transportSettings.getString("earlyDataHeaderName")
                                    ?: transportSettings.getString("early_data_header_name"))?.also {
                                    v2rayBean.earlyDataHeaderName = it
                                }
                            }
                        }
                        "meek" -> {
                            v2rayBean.type = "meek"
                            streamSettings.getObject("transportSettings")?.also { transportSettings ->
                                transportSettings.getString("url")?.also {
                                    v2rayBean.meekUrl = it
                                }
                            }
                        }
                        "mekya" -> {
                            v2rayBean.type = "mekya"
                            streamSettings.getObject("transportSettings")?.also { transportSettings ->
                                transportSettings.getString("url")?.also {
                                    v2rayBean.mekyaUrl = it
                                }
                                transportSettings.getObject("kcp")?.also { kcp ->
                                    kcp.getString("seed")?.also {
                                        v2rayBean.mekyaKcpSeed = it
                                    }
                                    (kcp.getObject("headerConfig")
                                        ?: kcp.getObject("header_config"))?.also { headerConfig ->
                                        when (headerConfig.getString("@type")) {
                                            null, "types.v2fly.org/v2ray.core.transport.internet.headers.noop.Config",
                                            "types.v2fly.org/v2ray.core.transport.internet.headers.noop.ConnectionConfig" -> v2rayBean.mekyaKcpHeaderType = "none"
                                            "types.v2fly.org/v2ray.core.transport.internet.headers.srtp.Config" -> v2rayBean.mekyaKcpHeaderType = "srtp"
                                            "types.v2fly.org/v2ray.core.transport.internet.headers.utp.Config" -> v2rayBean.mekyaKcpHeaderType = "utp"
                                            "types.v2fly.org/v2ray.core.transport.internet.headers.wechat.VideoConfig" -> v2rayBean.mekyaKcpHeaderType = "wechat-video"
                                            "types.v2fly.org/v2ray.core.transport.internet.headers.tls.PacketConfig" -> v2rayBean.mekyaKcpHeaderType = "dtls"
                                            "types.v2fly.org/v2ray.core.transport.internet.headers.wireguard.WireguardConfig" -> v2rayBean.mekyaKcpHeaderType = "wireguard"
                                            else -> return listOf()
                                        }
                                    }
                                }
                            }
                        }
                        "hysteria2" -> {
                            v2rayBean.type = "hysteria2"
                            streamSettings.getObject("transportSettings")?.also { transportSettings ->
                                transportSettings.getString("password")?.also {
                                    v2rayBean.hy2Password = it
                                }
                            }
                        }
                        else -> return listOf()
                    }
                }
            }

            outbound.getObject("settings")?.also { settings ->
                if (settings.contains("servers", ignoreCase = true) || settings.contains("vnext", ignoreCase = true)) { // jsonv4
                    return listOf()
                }
                settings.getString("address")?.also {
                    v2rayBean.serverAddress = it
                } ?: return listOf()
                settings.getInt("port")?.also {
                    v2rayBean.serverPort = it
                } ?: return listOf()
                when (type) {
                    "shadowsocks" -> {
                        v2rayBean as ShadowsocksBean
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
                    }
                    "trojan" -> {
                        v2rayBean as TrojanBean
                        settings.getString("password")?.also {
                            v2rayBean.password = it
                        }
                    }
                    "vmess" -> {
                        v2rayBean as VMessBean
                        settings.getString("uuid")?.also {
                            v2rayBean.uuid = it
                        }
                    }
                    "vless" -> {
                        v2rayBean as VLESSBean
                        settings.getString("uuid")?.also {
                            v2rayBean.uuid = it
                        }
                    }
                    "shadowsocks2022" -> {
                        v2rayBean as ShadowsocksBean
                        settings.getString("method")?.also {
                            if (it !in supportedShadowsocks2022Method)
                                return listOf()
                            v2rayBean.method = it
                        }
                        settings.getString("psk")?.also { psk ->
                            v2rayBean.password = psk
                            settings.getStringArray("ipsk")?.also { ipsk ->
                                v2rayBean.password = ipsk.joinToString(":") + ":" + psk
                            }
                        }
                    }
                }
            }
            return listOf(v2rayBean)
        }
        "hysteria2" -> {
            val hysteria2Bean = Hysteria2Bean().apply {
                outbound.getString("tag")?.also {
                    name = it
                }
            }
            outbound.getObject("streamSettings")?.also { streamSettings ->
                if (streamSettings.getString("security") != "tls") {
                    return listOf()
                }
                if (streamSettings.getString("transport") != "hysteria2") {
                    return listOf()
                }
                streamSettings.getObject("securitySettings")?. also { securitySettings ->
                    (securitySettings.getString("serverName")
                        ?: securitySettings.getString("server_name"))?.also {
                        hysteria2Bean.sni = it
                    }
                }
                streamSettings.getObject("transportSettings")?.also { transportSettings ->
                    transportSettings.getString("password")?.also {
                        hysteria2Bean.auth = it
                    }
                }
            }
            outbound.getObject("settings")?.also { settings ->
                settings.getArray("server")?.forEach { server ->
                    server.getString("address")?.also {
                        hysteria2Bean.serverAddress = it
                    } ?: return listOf()
                    server.getInt("port")?.also {
                        hysteria2Bean.serverPorts = it.toString()
                    } ?: return listOf()
                }
            } ?: return listOf()
            return listOf(hysteria2Bean)
        }
        else -> return listOf()
    }
}

private fun JsonObject.getInt(key: String): Int? {
    val value = get(key) ?: return null
    return when {
        value.isJsonPrimitive && value.asJsonPrimitive.isNumber -> {
            try {
                value.asInt
            } catch (_: Exception) {
                null
            }
        }
        value.isJsonPrimitive && value.asJsonPrimitive.isString -> value.asString.toIntOrNull()
        else -> null
    }
}
