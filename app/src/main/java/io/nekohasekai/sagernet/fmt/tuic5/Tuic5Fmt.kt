/******************************************************************************
 * Copyright (C) 2022 by nekohasekai <contact-git@sekai.icu>                  *
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

import cn.hutool.core.lang.UUID
import cn.hutool.json.JSONArray
import cn.hutool.json.JSONObject
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
import io.nekohasekai.sagernet.ktx.unwrapIDN
import java.io.File
import libcore.Libcore

val supportedTuic5CongestionControl = arrayOf("cubic", "bbr", "new_reno")
val supportedTuic5RelayMode = arrayOf("native", "quic")

fun parseTuic(server: String): AbstractBean {
    var link = Libcore.parseURL(server)
    try {
        // v2rayN broken format
        if (server.length > 46 && UUID.fromString(server.substring(7, 43)) != null && server.substring(43, 46) == "%3A" && !server.contains("version=")) {
            link = Libcore.parseURL(server.substring(0, 43) + ":" + server.substring(46, server.length))
        }
    } catch (_: Exception) {}
    val version = link.queryParameter("version")
    if (version == "4" || (version != "5" && link.password.isEmpty())) {
        return TuicBean().apply {
            serverAddress = link.host.unwrapIDN()
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
        serverAddress = link.host.unwrapIDN()
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
    if (allowInsecure) {
        builder.addQueryParameter("allow_insecure", "1")
    }
    return builder.string
}

fun Tuic5Bean.buildTuic5Config(port: Int, forExport: Boolean, cacheFile: (() -> File)?): String {
    return JSONObject().also {
        it["relay"] = JSONObject().also {
            if (sni.isNotEmpty()) {
                it["server"] = joinHostPort(sni, finalPort)
                it["ip"] = finalAddress
            } else {
                it["server"] = joinHostPort(serverAddress, finalPort)
                it["ip"] = finalAddress
            }
            it["uuid"] = uuid
            it["password"] = password

            if (caText.isNotEmpty() && cacheFile != null) {
                val caFile = cacheFile()
                caFile.writeText(caText)
                it["certificates"] = JSONArray().apply {
                    put(caFile.absolutePath)
                }
            } else if (!forExport && DataStore.providerRootCA == RootCAProvider.SYSTEM && caText.isEmpty()) {
                it["certificates"] = JSONArray().apply {
                    // https://github.com/maskedeken/tuic/commit/88e57f6e41ae8985edd8f620950e3f8e7d29e1cc
                    // workaround tuic can't load Android system root certificates without forking it
                    File("/system/etc/security/cacerts").listFiles()?.forEach { put(it) }
                }
            }

            it["udp_relay_mode"] = udpRelayMode
            if (alpn.isNotEmpty()) {
                it["alpn"] = JSONArray(alpn.listByLineOrComma())
            }
            it["congestion_control"] = congestionControl
            it["disable_sni"] = disableSNI
            it["zero_rtt_handshake"] = zeroRTTHandshake
            if (allowInsecure) {
                it["skip_cert_verify"] = true
            }
        }
        it["local"] = JSONObject().also {
            it["server"] = joinHostPort(LOCALHOST, port)
            it["max_packet_size"] = mtu
        }
        it["log_level"] = when (DataStore.logLevel) {
            LogLevel.DEBUG -> "trace"
            LogLevel.INFO -> "info"
            LogLevel.WARNING -> "warn"
            LogLevel.ERROR -> "error"
            else -> "error"
        }
    }.toStringPretty()
}