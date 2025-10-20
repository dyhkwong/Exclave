/******************************************************************************
 * Copyright (C) 2023 by dyhkwong                                             *
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

package io.nekohasekai.sagernet.fmt.tuic5

import io.nekohasekai.sagernet.LogLevel
import io.nekohasekai.sagernet.RootCAProvider
import io.nekohasekai.sagernet.database.DataStore
import io.nekohasekai.sagernet.fmt.AbstractBean
import io.nekohasekai.sagernet.fmt.LOCALHOST
import io.nekohasekai.sagernet.fmt.tuic.TuicBean
import io.nekohasekai.sagernet.fmt.tuic.supportedTuicCongestionControl
import io.nekohasekai.sagernet.fmt.tuic.supportedTuicRelayMode
import io.nekohasekai.sagernet.ktx.joinHostPort
import io.nekohasekai.sagernet.ktx.listByLineOrComma
import io.nekohasekai.sagernet.ktx.queryParameter
import io.nekohasekai.sagernet.ktx.toStringPretty
import java.io.File
import libcore.Libcore
import org.json.JSONArray
import org.json.JSONObject

val supportedTuic5CongestionControl = arrayOf("cubic", "bbr", "new_reno")
val supportedTuic5RelayMode = arrayOf("native", "quic")

fun parseTuic(server: String): AbstractBean {
    var link = Libcore.parseURL(server)
    if (server.length >= 46 && !server.contains("version=")
        && server.substring(7, 15).all {
            (it >= '0' && it <= '9') || (it >= 'a' && it <= 'f') || (it >= 'A' && it <= 'F')
        } && server.substring(15, 16) == "-"
        && server.substring(16, 20).all {
            (it >= '0' && it <= '9') || (it >= 'a' && it <= 'f') || (it >= 'A' && it <= 'F')
        } && server.substring(20, 21) == "-"
        && server.substring(21, 25).all {
            (it >= '0' && it <= '9') || (it >= 'a' && it <= 'f') || (it >= 'A' && it <= 'F')
        } && server.substring(25, 26) == "-"
        && server.substring(26, 30).all {
            (it >= '0' && it <= '9') || (it >= 'a' && it <= 'f') || (it >= 'A' && it <= 'F')
        } && server.substring(30, 31) == "-"
        && server.substring(31, 43).all {
            (it >= '0' && it <= '9') || (it >= 'a' && it <= 'f') || (it >= 'A' && it <= 'F')
        } && server.substring(43, 46) == "%3A"
    ) {
        // v2rayN broken format
        link = Libcore.parseURL(server.substring(0, 43) + ":" + server.substring(46, server.length))
    }
    val version = link.queryParameter("version")
    if (version == "4" || (version != "5" && link.password.isEmpty())) {
        return TuicBean().apply {
            serverAddress = link.host
            serverPort = link.port
            if (link.port == 0) {
                serverPort = 443
            }
            token = link.username
            link.queryParameter("sni")?.let {
                sni = it
            }
            link.queryParameter("alpn")?.let {
                alpn = it.split(",").joinToString("\n")
            }
            (link.queryParameter("congestion_controller") ?:
            link.queryParameter("congestion-controller") ?:
            link.queryParameter("congestion_control") ?:
            link.queryParameter("congestion-control"))?.let {
                congestionController = when (it) {
                    in supportedTuicCongestionControl -> it
                    "new-reno" -> "new_reno"
                    else -> "cubic"
                }
            }
            (link.queryParameter("udp-relay-mode") ?:
            link.queryParameter("udp_relay_mode") ?:
            link.queryParameter("udp-relay_mode") ?:
            link.queryParameter("udp_relay-mode"))?.let {
                udpRelayMode = when (it) {
                    in supportedTuicRelayMode -> it
                    else -> "native"
                }
            }
            (link.queryParameter("disable_sni") ?: link.queryParameter("disable-sni"))
                ?.takeIf { it == "1" || it == "true" }?.let {
                disableSNI = true
            }
            (link.queryParameter("reduce_rtt") ?: link.queryParameter("reduce-rtt"))
                ?.takeIf { it == "1" || it == "true" }?.let {
                reduceRTT = true
            }
            /*(link.queryParameter("allow_insecure") ?: link.queryParameter("allow-insecure") ?:
            link.queryParameter("insecure"))?.takeIf { it == "1" || it == "true" }?.let {
                allowInsecure = true
            }*/
            link.fragment?.let {
                name = it
            }
        }
    }
    return Tuic5Bean().apply {
        serverAddress = link.host
        serverPort = link.port
        if (link.port == 0) {
            serverPort = 443
        }
        uuid = link.username
        password = link.password
        link.queryParameter("sni")?.let {
            sni = it
        }
        link.queryParameter("alpn")?.let {
            alpn = it.split(",").joinToString("\n")
        }
        (link.queryParameter("congestion_controller") ?:
        link.queryParameter("congestion-controller") ?:
        link.queryParameter("congestion_control") ?:
        link.queryParameter("congestion-control"))?.let {
            congestionControl = when (it) {
                in supportedTuic5CongestionControl -> it
                "new-reno" -> "new_reno"
                else -> "cubic"
            }
        }
        (link.queryParameter("udp-relay-mode") ?:
        link.queryParameter("udp_relay_mode") ?:
        link.queryParameter("udp-relay_mode") ?:
        link.queryParameter("udp_relay-mode"))?.let {
            udpRelayMode = when (it) {
                in supportedTuic5RelayMode -> it
                else -> "native"
            }
        }
        (link.queryParameter("disable_sni") ?: link.queryParameter("disable-sni"))
            ?.takeIf { it == "1" || it == "true" }?.let {
                disableSNI = true
            }
        (link.queryParameter("reduce_rtt") ?: link.queryParameter("reduce-rtt"))
            ?.takeIf { it == "1" || it == "true" }?.let {
                zeroRTTHandshake = true
            }
        (link.queryParameter("allow_insecure") ?: link.queryParameter("allow-insecure") ?:
        link.queryParameter("insecure"))?.takeIf { it == "1" || it == "true" }?.let {
            allowInsecure = true
        }
        link.fragment?.let {
            name = it
        }
    }
}

fun Tuic5Bean.toUri(): String? {
    val builder = Libcore.newURL("tuic").apply {
        host = serverAddress.ifEmpty { error("empty server address") }
        port = serverPort
        username = uuid.ifEmpty { error("empty uuid") }
        if (name.isNotEmpty()) {
            fragment = name
        }
    }
    if (password.isNotEmpty()) {
        builder.password = password
    }
    builder.addQueryParameter("version", "5")
    builder.addQueryParameter("udp_relay_mode", udpRelayMode)
    builder.addQueryParameter("congestion_control", congestionControl)
    builder.addQueryParameter("congestion_controller", congestionControl)
    if (sni.isNotEmpty()) {
        builder.addQueryParameter("sni", sni)
    }
    if (alpn.isNotEmpty()) {
        builder.addQueryParameter("alpn", alpn.listByLineOrComma().joinToString(","))
    }
    if (disableSNI) {
        builder.addQueryParameter("disable_sni", "1")
    }
    if (zeroRTTHandshake) {
        builder.addQueryParameter("reduce_rtt", "1")
    }
    // as pinned certificate is not exportable, only add `allow_insecure=1` if pinned certificate is not used
    if (allowInsecure && pinnedPeerCertificateSha256.isEmpty() &&
        pinnedPeerCertificatePublicKeySha256.isEmpty() && pinnedPeerCertificateChainSha256.isEmpty()) {
        builder.addQueryParameter("allow_insecure", "1")
    }
    return builder.string
}

fun Tuic5Bean.buildTuic5Config(port: Int, forExport: Boolean, cacheFile: (() -> File)?): String {
    return JSONObject().also {
        it.put("relay", JSONObject().also {
            if (sni.isNotEmpty()) {
                it.put("server", joinHostPort(sni, finalPort))
                it.put("ip", finalAddress)
            } else {
                it.put("server", joinHostPort(serverAddress, finalPort))
                it.put("ip", finalAddress)
            }
            it.put("uuid", uuid)
            it.put("password", password)

            if (certificates.isNotEmpty() && cacheFile != null) {
                val caFile = cacheFile()
                caFile.writeText(certificates)
                it.put("certificates", JSONArray().apply {
                    put(caFile.absolutePath)
                })
            } else if (!forExport && DataStore.providerRootCA == RootCAProvider.SYSTEM && certificates.isEmpty()) {
                it.put("certificates", JSONArray().apply {
                    // https://github.com/maskedeken/tuic/commit/88e57f6e41ae8985edd8f620950e3f8e7d29e1cc
                    // workaround tuic can't load Android system root certificates without forking it
                    File("/system/etc/security/cacerts").listFiles()?.forEach { put(it) }
                })
            }

            it.put("udp_relay_mode", udpRelayMode)
            if (alpn.isNotEmpty()) {
                it.put("alpn", JSONArray(alpn.listByLineOrComma()))
            }
            it.put("congestion_control", congestionControl)
            it.put("disable_sni", disableSNI)
            it.put("zero_rtt_handshake", zeroRTTHandshake)
            if (allowInsecure) {
                it.put("skip_cert_verify", true)
            }
        })
        it.put("local", JSONObject().also {
            it.put("server", joinHostPort(LOCALHOST, port))
            it.put("max_packet_size", mtu)
        })
        it.put("log_level", when (DataStore.logLevel) {
            LogLevel.DEBUG -> "trace"
            LogLevel.INFO -> "info"
            LogLevel.WARNING -> "warn"
            LogLevel.ERROR -> "error"
            else -> "error"
        })
    }.toStringPretty()
}