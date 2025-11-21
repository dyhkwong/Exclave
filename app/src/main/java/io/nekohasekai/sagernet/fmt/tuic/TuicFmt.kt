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

package io.nekohasekai.sagernet.fmt.tuic

import com.google.gson.GsonBuilder
import com.google.gson.JsonArray
import com.google.gson.JsonObject
import io.nekohasekai.sagernet.LogLevel
import io.nekohasekai.sagernet.RootCAProvider
import io.nekohasekai.sagernet.database.DataStore
import io.nekohasekai.sagernet.fmt.LOCALHOST
import io.nekohasekai.sagernet.ktx.listByLineOrComma
import libcore.Libcore
import java.io.File

val supportedTuicCongestionControl = arrayOf("cubic", "bbr", "new_reno")
val supportedTuicRelayMode = arrayOf("native", "quic")

fun TuicBean.toUri(): String {
    // No standard at all. What a mess.
    val builder = Libcore.newURL("tuic").apply {
        host = serverAddress.ifEmpty { error("empty server address") }
        port = serverPort
        if (token.isNotEmpty()) {
            username = token
        }
        if (name.isNotEmpty()) {
            fragment = name
        }
    }
    builder.addQueryParameter("version", "4")
    builder.addQueryParameter("udp_relay_mode", udpRelayMode)
    builder.addQueryParameter("congestion_control", congestionController)
    builder.addQueryParameter("congestion_controller", congestionController)
    if (sni.isNotEmpty()) {
        builder.addQueryParameter("sni", sni)
    }
    if (alpn.isNotEmpty()) {
        builder.addQueryParameter("alpn", alpn.listByLineOrComma().joinToString(","))
    }
    if (disableSNI) {
        builder.addQueryParameter("disable_sni", "1")
    }
    if (reduceRTT) {
        builder.addQueryParameter("reduce_rtt", "1")
    }
    return builder.string
}

fun TuicBean.buildTuicConfig(port: Int, forExport: Boolean, cacheFile: (() -> File)?): String {
    return GsonBuilder().setPrettyPrinting().create().toJson(JsonObject().apply {
        add("relay", JsonObject().apply {
            if (sni.isNotEmpty()) {
                addProperty("server", sni)
                addProperty("ip", finalAddress)
            } else {
                addProperty("server", serverAddress)
                addProperty("ip", finalAddress)
            }
            addProperty("port", finalPort)
            addProperty("token", token)

            if (caText.isNotEmpty() && cacheFile != null) {
                val caFile = cacheFile()
                caFile.writeText(caText)
                add("certificates", JsonArray().apply {
                    add(caFile.absolutePath)
                })
            } else if (!forExport && DataStore.providerRootCA == RootCAProvider.SYSTEM && caText.isEmpty()) {
                add("certificates", JsonArray().apply {
                    // workaround tuic can't load Android system root certificates without forking it
                    File("/system/etc/security/cacerts").listFiles()?.forEach { add(it.absolutePath) }
                })
            }

            addProperty("udp_relay_mode", udpRelayMode)
            if (alpn.isNotEmpty()) {
                add("alpn", JsonArray().apply {
                    alpn.listByLineOrComma().forEach { add(it) }
                })
            }
            addProperty("congestion_controller", congestionController)
            addProperty("disable_sni", disableSNI)
            addProperty("reduce_rtt", reduceRTT)
            addProperty("max_udp_relay_packet_size", mtu)
        })
        add("local", JsonObject().apply {
            addProperty("ip", LOCALHOST)
            addProperty("port", port)
        })
        addProperty("log_level", when (DataStore.logLevel) {
            LogLevel.DEBUG -> "trace"
            LogLevel.INFO -> "info"
            LogLevel.WARNING -> "warn"
            LogLevel.ERROR -> "error"
            else -> "off"
        })
    })
}