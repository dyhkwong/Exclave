package io.nekohasekai.sagernet.group

import cn.hutool.json.JSONObject
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

@Suppress("UNCHECKED_CAST")
fun parseV2ray5Outbound(outbound: JSONObject): List<AbstractBean> {
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
                if (streamSettings.contains("network") || streamSettings.contains("tlsSettings")
                    || streamSettings.contains("tcpSettings") || streamSettings.contains("kcpSettings")
                    || streamSettings.contains("wsSettings") || streamSettings.contains("httpSettings")
                    || streamSettings.contains("grpcSettings") || streamSettings.contains("gunSettings")
                    || streamSettings.contains("quicSettings") || streamSettings.contains("hy2Settings")) { // jsonv4
                    return listOf()
                }
                streamSettings.getString("security")?.also { security ->
                    when (security) {
                        "none" -> {}
                        "tls", "utls" -> {
                            v2rayBean.security = "tls"
                            val securitySettings = streamSettings.getObject("securitySettings")
                            val tls = if (security == "tls") {
                                securitySettings
                            } else {
                                securitySettings?.get("tlsConfig") as? JSONObject
                                    ?: securitySettings?.get("tls_config") as? JSONObject
                            }
                            tls?.also { tlsConfig ->
                                (tlsConfig["serverName"]?.toString() ?: tlsConfig["server_name"]?.toString())?.also {
                                    v2rayBean.sni = it
                                }
                                (tlsConfig["pinnedPeerCertificateChainSha256"] as? List<String>
                                    ?: tlsConfig["pinned_peer_certificate_chain_sha256"] as? List<String>)?.also {
                                    v2rayBean.pinnedPeerCertificateChainSha256 = it.joinToString("\n")
                                    (tlsConfig["allowInsecureIfPinnedPeerCertificate"] as? Boolean
                                        ?: tlsConfig["allow_insecure_if_pinned_peer_certificate"] as? Boolean)?.also { allowInsecure ->
                                        v2rayBean.allowInsecure = allowInsecure
                                    }
                                }
                                (tlsConfig["nextProtocol"] as? List<String>)?.also {
                                    v2rayBean.alpn = it.joinToString("\n")
                                } ?: (tlsConfig["next_protocol"] as? List<String>)?.also {
                                    v2rayBean.alpn = it.joinToString("\n")
                                }
                                // tlsConfig["imitate"]
                            }
                        }
                        else -> return listOf()
                    }
                }
                streamSettings.getString("transport")?.also { transport ->
                    when (transport) {
                        "tcp" -> {
                            v2rayBean.type = "tcp"
                            streamSettings.getObject("transportSettings")?.also { transportSettings ->
                                (transportSettings["headerSettings"] as? JSONObject)
                                    ?: (transportSettings["header_settings"] as? JSONObject)?.also { headerSettings ->
                                        when (headerSettings["@type"] as? String) {
                                            "v2ray.core.transport.internet.headers.http.Config" -> {
                                                v2rayBean.headerType = "http"
                                                (headerSettings["request"] as? JSONObject)?.also { request ->
                                                    (request["uri"] as? List<String>)?.also {
                                                        v2rayBean.path = it.joinToString("\n")
                                                    }
                                                    (request.getAny("header") as? Map<String, List<String>>)?.forEach { (key, value) ->
                                                        when (key.lowercase()) {
                                                            "host" -> {
                                                                v2rayBean.host = value.joinToString("\n")
                                                            }
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
                                transportSettings["seed"]?.toString()?.also {
                                    v2rayBean.mKcpSeed = it
                                }
                                when ((transportSettings["headerConfig"] as? JSONObject)?.get("@type") as? String
                                    ?: (transportSettings["header_config"] as? JSONObject)?.get("@type") as? String) {
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
                        "ws" -> {
                            v2rayBean.type = "ws"
                            streamSettings.getObject("transportSettings")?.also { transportSettings ->
                                transportSettings["path"]?.toString()?.also {
                                    v2rayBean.path = it
                                }
                                (transportSettings["maxEarlyData"]?.toString()?.toInt()
                                    ?: transportSettings["max_early_data"]?.toString()?.toInt())?.also {
                                    v2rayBean.maxEarlyData = it
                                }
                                (transportSettings["earlyDataHeaderName"]?.toString()
                                    ?: transportSettings["early_data_header_name"]?.toString())?.also {
                                    v2rayBean.earlyDataHeaderName = it
                                }
                                (transportSettings["header"] as? Map<String, String>)?.forEach { (key, value) ->
                                    when (key.lowercase()) {
                                        "host" -> {
                                            v2rayBean.host = value
                                        }
                                    }
                                }
                            }
                        }
                        "h2" -> {
                            v2rayBean.type = "http"
                            streamSettings.getObject("transportSettings")?.also { transportSettings ->
                                transportSettings["path"]?.toString()?.also {
                                    v2rayBean.path = it
                                }
                                (transportSettings["host"] as? List<String>)?.also {
                                    v2rayBean.host = it.joinToString("\n")
                                }
                            }
                        }
                        "quic" -> {
                            v2rayBean.type = "quic"
                            streamSettings.getObject("transportSettings")?.also { transportSettings ->
                                transportSettings["security"]?.toString()?.lowercase()?.also {
                                    if (it !in supportedQuicSecurity) return listOf()
                                    v2rayBean.quicSecurity = it
                                }
                                transportSettings["key"]?.toString()?.also {
                                    v2rayBean.quicKey = it
                                }
                                when ((transportSettings["header"] as? JSONObject)?.get("@type") as? String) {
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
                        "grpc" -> {
                            v2rayBean.type = "grpc"
                            streamSettings.getObject("transportSettings")?.also { transportSettings ->
                                (transportSettings["serviceName"]?.toString()
                                    ?: transportSettings["service_name"]?.toString())?.also {
                                    v2rayBean.grpcServiceName = it
                                }
                            }
                        }
                        "httpupgrade" -> {
                            v2rayBean.type = "httpupgrade"
                            streamSettings.getObject("transportSettings")?.also { transportSettings ->
                                transportSettings["path"]?.toString()?.also {
                                    v2rayBean.path = it
                                }
                                transportSettings["host"]?.toString()?.also {
                                    v2rayBean.host = it
                                }
                                (transportSettings["maxEarlyData"]?.toString()?.toInt()
                                    ?: transportSettings["max_early_data"]?.toString()?.toInt())?.also {
                                    v2rayBean.maxEarlyData = it
                                }
                                (transportSettings["earlyDataHeaderName"]?.toString()
                                    ?: transportSettings["early_data_header_name"]?.toString())?.also {
                                    v2rayBean.earlyDataHeaderName = it
                                }
                            }
                        }
                        "meek" -> {
                            v2rayBean.type = "meek"
                            streamSettings.getObject("transportSettings")?.also { transportSettings ->
                                transportSettings["url"]?.toString()?.also {
                                    v2rayBean.meekUrl = it
                                }
                            }
                        }
                        "mekya" -> {
                            v2rayBean.type = "mekya"
                            streamSettings.getObject("transportSettings")?.also { transportSettings ->
                                transportSettings["url"]?.toString()?.also {
                                    v2rayBean.mekyaUrl = it
                                }
                                (transportSettings["kcp"] as? JSONObject)?.also { kcp ->
                                    kcp["seed"]?.toString()?.also {
                                        v2rayBean.mekyaKcpSeed = it
                                    }
                                    when ((kcp["headerConfig"] as? JSONObject)?.get("@type") as? String
                                        ?: (kcp["header_config"] as? JSONObject)?.get("@type") as? String) {
                                        null, "types.v2fly.org/v2ray.core.transport.internet.headers.noop.Config",
                                        "types.v2fly.org/v2ray.core.transport.internet.headers.noop.ConnectionConfig" -> v2rayBean.headerType = "none"
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
                        "hysteria2" -> {
                            v2rayBean.type = "hysteria2"
                            streamSettings.getObject("transportSettings")?.also { transportSettings ->
                                transportSettings["password"]?.toString()?.also {
                                    v2rayBean.hy2Password = it
                                }
                                /*(transportSettings["congestion"] as? JSONObject)?.also { congestion ->
                                    (congestion["up_mbps"] as? Int ?: congestion["upMbps"] as? Int)?.also {
                                        v2rayBean.hy2UpMbps = it
                                    }
                                    (congestion["down_mbps"] as? Int ?: congestion["downMbps"] as? Int)?.also {
                                        v2rayBean.hy2DownMbps = it
                                    }
                                }*/
                            }
                        }
                        else -> return listOf()
                    }
                }
            }

            (outbound["settings"] as? JSONObject)?.also { settings ->
                if (settings.containsKey("servers") || settings.containsKey("vnext")) { // jsonv4
                    return listOf()
                }
                settings["address"]?.toString()?.also {
                    v2rayBean.serverAddress = it
                } ?: return listOf()
                settings["port"]?.toString()?.toInt()?.also {
                    v2rayBean.serverPort = it
                } ?: return listOf()
                when (type) {
                    "shadowsocks" -> {
                        v2rayBean as ShadowsocksBean
                        settings["method"]?.toString()?.lowercase()?.also {
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
                        settings["password"]?.toString()?.also {
                            v2rayBean.password = it
                        }
                    }
                    "trojan" -> {
                        v2rayBean as TrojanBean
                        settings["password"]?.toString()?.also {
                            v2rayBean.password = it
                        }
                    }
                    "vmess" -> {
                        v2rayBean as VMessBean
                        settings["uuid"]?.toString()?.also {
                            v2rayBean.uuid = it
                        }
                    }
                    "vless" -> {
                        v2rayBean as VLESSBean
                        settings["uuid"]?.toString()?.also {
                            v2rayBean.uuid = it
                        }
                    }
                    "shadowsocks2022" -> {
                        v2rayBean as ShadowsocksBean
                        settings["method"]?.toString()?.also {
                            if (it !in supportedShadowsocks2022Method)
                                return listOf()
                            v2rayBean.method = it
                        }
                        settings["psk"]?.toString()?.also { psk ->
                            v2rayBean.password = psk
                            (settings["ipsk"] as? List<String>)?.also { ipsk ->
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
                    (securitySettings["serverName"]?.toString() ?: securitySettings["server_name"]?.toString())?.also {
                        hysteria2Bean.sni = it
                    }
                }
                streamSettings.getObject("transportSettings")?.also { transportSettings ->
                    transportSettings["password"]?.toString()?.also {
                        hysteria2Bean.auth = it
                    }
                    /*(transportSettings["congestion"] as? JSONObject)?.also { congestion ->
                        (congestion["up_mbps"]?.toString()?.toInt()?: congestion["upMbps"]?.toString()?.toInt())?.also {
                            hysteria2Bean.uploadMbps = it
                        }
                        (congestion["down_mbps"]?.toString()?.toInt() ?: congestion["downMbps"]?.toString()?.toInt())?.also {
                            hysteria2Bean.downloadMbps = it
                        }
                    }*/
                }
            }
            outbound.getObject("settings")?.also { settings ->
                (settings["server"] as? List<JSONObject>)?.forEach { server ->

                    server["address"]?.toString()?.also {
                        hysteria2Bean.serverAddress = it
                    } ?: return listOf()
                    (server["port"]?.toString()?.toInt())?.also {
                        hysteria2Bean.serverPorts = it.toString()
                    } ?: return listOf()
                }
            } ?: return listOf()
            return listOf(hysteria2Bean)
        }
        else -> return listOf()
    }
}