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
import io.nekohasekai.sagernet.ktx.filterIsInstance
import io.nekohasekai.sagernet.ktx.optBooleanOrNull
import io.nekohasekai.sagernet.ktx.optStringOrNull
import org.json.JSONObject
import kotlin.io.encoding.Base64

@Suppress("UNCHECKED_CAST")
fun parseV2ray5Outbound(outbound: JSONObject): List<AbstractBean> {
    when (val type = outbound.optStringOrNull("protocol")) {
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
                outbound.optStringOrNull("tag")?.also {
                    name = it
                }
            }
            outbound.optJSONObject("streamSettings")?.also { streamSettings ->
                if (streamSettings.hasCaseInsensitive("network") || streamSettings.hasCaseInsensitive("tlsSettings")
                    || streamSettings.hasCaseInsensitive("xtlsSettings") || streamSettings.hasCaseInsensitive("utlsSettings")
                    || streamSettings.hasCaseInsensitive("tcpSettings") || streamSettings.hasCaseInsensitive("kcpSettings")
                    || streamSettings.hasCaseInsensitive("wsSettings") || streamSettings.hasCaseInsensitive("httpSettings")
                    || streamSettings.hasCaseInsensitive("grpcSettings") || streamSettings.hasCaseInsensitive("gunSettings")
                    || streamSettings.hasCaseInsensitive("quicSettings") || streamSettings.hasCaseInsensitive("hy2Settings")
                    || streamSettings.hasCaseInsensitive("rawSettings") || streamSettings.hasCaseInsensitive("splithttpSettings")
                    || streamSettings.hasCaseInsensitive("xhttpSettings")
                ) { // jsonv4
                    return listOf()
                }
                streamSettings.optStringOrNull("security")?.also { security ->
                    when (security) {
                        "none", "" -> {}
                        "tls", "utls" -> {
                            v2rayBean.security = "tls"
                            val securitySettings = streamSettings.optJSONObject("securitySettings")
                            val tls = if (security == "tls") {
                                securitySettings
                            } else {
                                securitySettings?.optJSONObject("tlsConfig")
                                    ?: securitySettings?.optJSONObject("tls_config")
                            }
                            tls?.also { tlsConfig ->
                                (tlsConfig.optStringOrNull("serverName") ?: tlsConfig.optStringOrNull("server_name"))?.also {
                                    v2rayBean.sni = it
                                }
                                tlsConfig.optJSONArray("nextProtocol")?.filterIsInstance<String>()?.also {
                                    v2rayBean.alpn = it.joinToString("\n")
                                } ?: tlsConfig.optJSONArray("next_protocol")?.filterIsInstance<String>()?.also {
                                    v2rayBean.alpn = it.joinToString("\n")
                                }
                                tlsConfig.optJSONArray("certificate")?.filterIsInstance<JSONObject>()?.asReversed()?.forEach { certificate ->
                                    when (certificate.optStringOrNull("usage")) {
                                        null, "ENCIPHERMENT" -> {
                                            if (!certificate.has("certificateFile") && !certificate.has("certificate_file")
                                                && !certificate.has("keyFile") && !certificate.has("key_file")) {
                                                val cert = certificate.optStringOrNull("Certificate")?.takeIf {
                                                    it.contains("-----BEGIN ") && it.contains("-----END ") && it.contains(" CERTIFICATE-----")
                                                }
                                                val key = certificate.optStringOrNull("Key")?.takeIf {
                                                    it.contains("-----BEGIN ") && it.contains("-----END ") && it.contains(" PRIVATE KEY-----")
                                                }
                                                if (cert != null && key != null) {
                                                    v2rayBean.mtlsCertificate = String(Base64.decode(cert))
                                                    v2rayBean.mtlsCertificatePrivateKey = String(Base64.decode(key))
                                                }
                                            }
                                        }
                                        "AUTHORITY_VERIFY" -> {
                                            if (!certificate.has("certificateFile") && !certificate.has("certificate_file")) {
                                                val cert = certificate.optStringOrNull("Certificate")?.takeIf {
                                                    it.contains("-----BEGIN ") && it.contains("-----END ") && it.contains(" CERTIFICATE-----")
                                                }
                                                if (cert != null) {
                                                    v2rayBean.certificates = cert
                                                }
                                            }
                                        }
                                    }
                                }
                                (tlsConfig.optJSONArray("pinnedPeerCertificateChainSha256")?.filterIsInstance<String>()
                                    ?: tlsConfig.optJSONArray("pinned_peer_certificate_chain_sha256")?.filterIsInstance<String>())?.also {
                                    v2rayBean.pinnedPeerCertificateChainSha256 = it.joinToString("\n")
                                    (tlsConfig.optBooleanOrNull("allowInsecureIfPinnedPeerCertificate")
                                        ?: tlsConfig.optBooleanOrNull("allow_insecure_if_pinned_peer_certificate"))?.also { allowInsecure ->
                                        v2rayBean.allowInsecure = allowInsecure
                                    }
                                }
                            }
                        }
                        else -> return listOf()
                    }
                }
                streamSettings.optStringOrNull("transport")?.also { transport ->
                    when (transport) {
                        "tcp", "" -> {
                            v2rayBean.type = "tcp"
                            streamSettings.optJSONObject("transportSettings")?.also { transportSettings ->
                                (transportSettings.optJSONObject("headerSettings")
                                    ?: transportSettings.optJSONObject("header_settings"))?.also { headerSettings ->
                                        when (headerSettings.optStringOrNull("@type")) {
                                            "v2ray.core.transport.internet.headers.http.Config" -> {
                                                v2rayBean.headerType = "http"
                                                headerSettings.optJSONObject("request")?.also { request ->
                                                    request.optJSONArray("uri")?.filterIsInstance<String>()?.also {
                                                        v2rayBean.path = it.joinToString("\n")
                                                    }
                                                    request.optJSONArray("header")?.filterIsInstance<JSONObject>()?.forEach {
                                                        if (it.optStringOrNull("name")?.lowercase() == "host") {
                                                            v2rayBean.host = it.optJSONArray("value")?.filterIsInstance<String>()?.joinToString("\n")
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
                            streamSettings.optJSONObject("transportSettings")?.also { transportSettings ->
                                transportSettings.optStringOrNull("seed")?.also {
                                    v2rayBean.mKcpSeed = it
                                }
                                (transportSettings.optJSONObject("headerConfig")
                                    ?: transportSettings.optJSONObject("header_config"))?.also { headerConfig ->
                                    when (headerConfig.optStringOrNull("@type")) {
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
                            streamSettings.optJSONObject("transportSettings")?.also { transportSettings ->
                                transportSettings.optStringOrNull("path")?.also {
                                    v2rayBean.path = it
                                }
                                (transportSettings.optV2Ray5Int("maxEarlyData")
                                    ?: transportSettings.optV2Ray5Int("max_early_data"))?.also {
                                    v2rayBean.maxEarlyData = it
                                }
                                (transportSettings.optStringOrNull("earlyDataHeaderName")
                                    ?: transportSettings.optStringOrNull("early_data_header_name"))?.also {
                                    v2rayBean.earlyDataHeaderName = it
                                }
                                transportSettings.optJSONArray("header")?.filterIsInstance<JSONObject>()?.forEach {
                                    if (it.optStringOrNull("key")?.lowercase() == "host") {
                                        v2rayBean.host = it.optJSONArray("value")?.filterIsInstance<String>()?.joinToString("\n")
                                    }
                                }
                            }
                        }
                        "h2" -> {
                            v2rayBean.type = "http"
                            streamSettings.optJSONObject("transportSettings")?.also { transportSettings ->
                                transportSettings.optStringOrNull("path")?.also {
                                    v2rayBean.path = it
                                }
                                transportSettings.optJSONArray("host")?.filterIsInstance<String>()?.also {
                                    v2rayBean.host = it.joinToString("\n")
                                }
                            }
                        }
                        "quic" -> {
                            v2rayBean.type = "quic"
                            streamSettings.optJSONObject("transportSettings")?.also { transportSettings ->
                                transportSettings.optStringOrNull("security")?.lowercase()?.also {
                                    if (it !in supportedQuicSecurity) return listOf()
                                    v2rayBean.quicSecurity = it
                                }
                                transportSettings.optStringOrNull("key")?.also {
                                    v2rayBean.quicKey = it
                                }
                                (transportSettings.optJSONObject("headerConfig")
                                    ?: transportSettings.optJSONObject("header_config"))?.also { headerConfig ->
                                    when (headerConfig.optStringOrNull("@type")) {
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
                            streamSettings.optJSONObject("transportSettings")?.also { transportSettings ->
                                (transportSettings.optStringOrNull("serviceName")
                                    ?: transportSettings.optStringOrNull("service_name"))?.also {
                                    v2rayBean.grpcServiceName = it
                                }
                            }
                        }
                        "httpupgrade" -> {
                            v2rayBean.type = "httpupgrade"
                            streamSettings.optJSONObject("transportSettings")?.also { transportSettings ->
                                transportSettings.optStringOrNull("path")?.also {
                                    v2rayBean.path = it
                                }
                                transportSettings.optStringOrNull("host")?.also {
                                    v2rayBean.host = it
                                }
                                (transportSettings.optV2Ray5Int("maxEarlyData")
                                    ?: transportSettings.optV2Ray5Int("max_early_data"))?.also {
                                    v2rayBean.maxEarlyData = it
                                }
                                (transportSettings.optStringOrNull("earlyDataHeaderName")
                                    ?: transportSettings.optStringOrNull("early_data_header_name"))?.also {
                                    v2rayBean.earlyDataHeaderName = it
                                }
                            }
                        }
                        "meek" -> {
                            v2rayBean.type = "meek"
                            streamSettings.optJSONObject("transportSettings")?.also { transportSettings ->
                                transportSettings.optStringOrNull("url")?.also {
                                    v2rayBean.meekUrl = it
                                }
                            }
                        }
                        "mekya" -> {
                            v2rayBean.type = "mekya"
                            streamSettings.optJSONObject("transportSettings")?.also { transportSettings ->
                                transportSettings.optStringOrNull("url")?.also {
                                    v2rayBean.mekyaUrl = it
                                }
                                transportSettings.optJSONObject("kcp")?.also { kcp ->
                                    kcp.optStringOrNull("seed")?.also {
                                        v2rayBean.mekyaKcpSeed = it
                                    }
                                    (kcp.optJSONObject("headerConfig")
                                        ?: kcp.optJSONObject("header_config"))?.also { headerConfig ->
                                        when (headerConfig.optStringOrNull("@type")) {
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
                            streamSettings.optJSONObject("transportSettings")?.also { transportSettings ->
                                transportSettings.optStringOrNull("password")?.also {
                                    v2rayBean.hy2Password = it
                                }
                            }
                        }
                        else -> return listOf()
                    }
                }
            }

            outbound.optJSONObject("settings")?.also { settings ->
                if (settings.hasCaseInsensitive("servers") || settings.hasCaseInsensitive("vnext")) { // jsonv4
                    return listOf()
                }
                settings.optStringOrNull("address")?.also {
                    v2rayBean.serverAddress = it
                } ?: return listOf()
                settings.optV2Ray5Int("port")?.also {
                    v2rayBean.serverPort = it
                } ?: return listOf()
                when (type) {
                    "shadowsocks" -> {
                        v2rayBean as ShadowsocksBean
                        settings.optStringOrNull("method")?.lowercase()?.also {
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
                        settings.optStringOrNull("password")?.also {
                            v2rayBean.password = it
                        }
                    }
                    "trojan" -> {
                        v2rayBean as TrojanBean
                        settings.optStringOrNull("password")?.also {
                            v2rayBean.password = it
                        }
                    }
                    "vmess" -> {
                        v2rayBean as VMessBean
                        settings.optStringOrNull("uuid")?.also {
                            v2rayBean.uuid = it
                        }
                    }
                    "vless" -> {
                        v2rayBean as VLESSBean
                        settings.optStringOrNull("uuid")?.also {
                            v2rayBean.uuid = it
                        }
                    }
                    "shadowsocks2022" -> {
                        v2rayBean as ShadowsocksBean
                        settings.optStringOrNull("method")?.also {
                            if (it !in supportedShadowsocks2022Method)
                                return listOf()
                            v2rayBean.method = it
                        }
                        settings.optStringOrNull("psk")?.also { psk ->
                            v2rayBean.password = psk
                            settings.optJSONArray("ipsk")?.filterIsInstance<String>()?.also { ipsk ->
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
                outbound.optStringOrNull("tag")?.also {
                    name = it
                }
            }
            outbound.optJSONObject("streamSettings")?.also { streamSettings ->
                if (streamSettings.optStringOrNull("security") != "tls") {
                    return listOf()
                }
                if (streamSettings.optStringOrNull("transport") != "hysteria2") {
                    return listOf()
                }
                streamSettings.optJSONObject("securitySettings")?. also { securitySettings ->
                    (securitySettings.optStringOrNull("serverName")
                        ?: securitySettings.optStringOrNull("server_name"))?.also {
                        hysteria2Bean.sni = it
                    }
                }
                streamSettings.optJSONObject("transportSettings")?.also { transportSettings ->
                    transportSettings.optStringOrNull("password")?.also {
                        hysteria2Bean.auth = it
                    }
                }
            }
            outbound.optJSONObject("settings")?.also { settings ->
                settings.optJSONArray("server")?.filterIsInstance<JSONObject>()?.forEach { server ->
                    server.optStringOrNull("address")?.also {
                        hysteria2Bean.serverAddress = it
                    } ?: return listOf()
                    server.optV2Ray5Int("port")?.also {
                        hysteria2Bean.serverPorts = it.toString()
                    } ?: return listOf()
                }
            } ?: return listOf()
            return listOf(hysteria2Bean)
        }
        else -> return listOf()
    }
}

private fun JSONObject.optV2Ray5Int(key: String): Int? {
    if (this.has(key)) {
        return when (val value = this.opt(key)) {
            is Int -> return value
            is String -> return value.toInt()
            else -> null
        }
    }
    return null
}