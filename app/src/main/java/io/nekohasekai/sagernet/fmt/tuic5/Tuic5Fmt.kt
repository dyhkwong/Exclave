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
import io.nekohasekai.sagernet.ktx.joinHostPort
import io.nekohasekai.sagernet.ktx.listByLineOrComma
import io.nekohasekai.sagernet.ktx.queryParameter
import io.nekohasekai.sagernet.ktx.urlSafe
import java.io.File
import libcore.Libcore

fun parseTuic(server: String): AbstractBean {
    val link = if (server.length > 46 && UUID.fromString(server.substring(7, 43)) != null && server.substring(43, 46) == "%3A" && !server.contains("version=")) {
        // v2rayN broken format
        Libcore.parseURL(server.substring(0, 43) + ":" + server.substring(46, server.length))
    } else {
        Libcore.parseURL(server)
    }
    link.queryParameter("version")?.let { version ->
        if (version == "4" || link.password.isEmpty()) {
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
                link.queryParameter("congestion_controller")?.let {
                    congestionController = it
                }
                link.queryParameter("congestion_control")?.let {
                    congestionController = it
                }
                link.queryParameter("udp_relay-mode")?.let {
                    udpRelayMode = it
                }
                link.queryParameter("udp_relay_mode")?.let {
                    udpRelayMode = it
                }
                link.queryParameter("alpn")?.let {
                    alpn = it.split(",").joinToString("\n")
                }
                link.queryParameter("disable_sni")?.let {
                    disableSNI = it == "1" || it == "true"
                }
                link.fragment.takeIf { !it.isNullOrEmpty() }?.let {
                    name = it
                }
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
        link.queryParameter("congestion_controller")?.let {
            congestionControl = it
        }
        link.queryParameter("congestion_control")?.let {
            congestionControl = it
        }
        link.queryParameter("udp_relay-mode")?.let {
            udpRelayMode = it
        }
        link.queryParameter("udp_relay_mode")?.let {
            udpRelayMode = it
        }
        link.queryParameter("alpn")?.let {
            alpn = it.split(",").joinToString("\n")
        }
        link.queryParameter("disable_sni")?.let {
            disableSNI = it == "1" || it == "true"
        }
        link.queryParameter("allow_insecure")?.let {
            allowInsecure = it == "1" || it == "true"
        } ?: link.queryParameter("insecure")?.let {
            allowInsecure = it == "1" || it == "true"
        }
        link.fragment.takeIf { !it.isNullOrEmpty() }?.let {
            name = it
        }
    }
}

fun Tuic5Bean.toUri(): String {
    val builder = Libcore.newURL("tuic")
    builder.host = serverAddress
    builder.port = serverPort
    builder.username = uuid
    builder.password = password
    builder.addQueryParameter("version", "5")
    builder.addQueryParameter("udp_relay_mode", udpRelayMode)

    builder.addQueryParameter("congestion_control", congestionControl)

    if (sni.isNotEmpty()) {
        builder.addQueryParameter("sni", sni)
    }
    if (alpn.isNotEmpty()) {
        builder.addQueryParameter("alpn", alpn.listByLineOrComma().joinToString(","))
    }
    if (disableSNI) {
        builder.addQueryParameter("disable_sni", "1")
    }
    if (allowInsecure) {
        builder.addQueryParameter("allow_insecure", "1")
        builder.addQueryParameter("insecure", "1")
    }
    if (name.isNotEmpty()) {
        builder.setRawFragment(name.urlSafe())
    }
    builder.addQueryParameter("udp_relay-mode", udpRelayMode)
    builder.addQueryParameter("congestion_controller", congestionControl)
    return builder.string
}

fun Tuic5Bean.buildTuic5Config(port: Int, cacheFile: (() -> File)?): String {
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
            } else if (DataStore.providerRootCA == RootCAProvider.SYSTEM && caText.isEmpty()) {
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
            else -> "off"
        }
    }.toStringPretty()
}