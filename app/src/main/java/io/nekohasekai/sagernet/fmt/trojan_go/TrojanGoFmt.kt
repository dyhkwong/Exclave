/******************************************************************************
 *                                                                            *
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

package io.nekohasekai.sagernet.fmt.trojan_go

import com.google.gson.GsonBuilder
import com.google.gson.JsonArray
import com.google.gson.JsonObject
import io.nekohasekai.sagernet.LogLevel
import io.nekohasekai.sagernet.database.DataStore
import io.nekohasekai.sagernet.fmt.LOCALHOST
import io.nekohasekai.sagernet.ktx.queryParameter
import libcore.Libcore

fun parseTrojanGo(server: String): TrojanGoBean {
    val link = Libcore.parseURL(server)

    return TrojanGoBean().apply {
        serverAddress = link.host
        serverPort = link.port
        password = link.username
        link.queryParameter("sni")?.let {
            sni = it
        }
        link.queryParameter("type")?.let {
            when (it) {
                "original" -> type = "none"
                "ws" -> {
                    type = it
                    host = link.queryParameter("host")
                    path = link.queryParameter("path")
                }
                else -> error("unsupported protocol")
            }
        }
        link.queryParameter("encryption")?.let {
            encryption = when {
                it == "none" -> it
                it.startsWith("ss;aes-128-gcm:") ||
                        it.startsWith("ss;aes-256-gcm:") ||
                        it.startsWith("ss;chacha20-ietf-poly1305:") -> it
                else -> error("unsupported encryption")
            }
        }
        link.queryParameter("plugin")?.takeIf { it.isNotEmpty() }?.let {
            error("plugin not supported")
        }
        link.fragment?.let {
            name = it
        }
    }
}

fun TrojanGoBean.toUri(): String? {
    val builder = Libcore.newURL("trojan-go").apply {
        host = serverAddress.ifEmpty { error("empty server address") }
        port = serverPort
        if (password.isEmpty()) {
            username = password
        }
        if (name.isNotEmpty()) {
            fragment = name
        }
    }

    if (sni.isNotEmpty()) {
        builder.addQueryParameter("sni", sni)
    }
    when (type) {
        "ws" -> {
            builder.addQueryParameter("type", type)
            if (host.isNotEmpty()) {
                builder.addQueryParameter("host", host)
            }
            if (path.isNotEmpty()) {
                builder.addQueryParameter("path", path)
            }
        }
    }
    if (encryption != "none") {
        builder.addQueryParameter("encryption", encryption)
    }
    return builder.string
}

fun TrojanGoBean.buildTrojanGoConfig(port: Int): String {
    return GsonBuilder().setPrettyPrinting().create().toJson(JsonObject().apply {
        addProperty("run_type", "client")
        addProperty("local_addr", LOCALHOST)
        addProperty("local_port", port)
        addProperty("remote_addr", finalAddress)
        addProperty("remote_port", finalPort)
        add("password", JsonArray().apply {
            add(password)
        })
        addProperty("log_level", when (DataStore.logLevel) {
            LogLevel.DEBUG -> 0
            LogLevel.INFO -> 1
            LogLevel.WARNING -> 2
            LogLevel.ERROR -> 3
            else -> 5
        })
        if (mux) add("mux", JsonObject().apply {
            addProperty("enabled", true)
            addProperty("concurrency", muxConcurrency)
        })

        when (type) {
            "ws" -> add("websocket", JsonObject().apply {
                addProperty("enabled", true)
                addProperty("host", host)
                addProperty("path", path)
            })
        }

        var servername = sni
        if (servername.isEmpty()) {
            servername = serverAddress
        }

        add("ssl", JsonObject().apply {
            if (servername.isNotEmpty()) addProperty("sni", servername)
            if (allowInsecure) addProperty("verify", false)
            if (utlsFingerprint.isNotEmpty()) addProperty("fingerprint", utlsFingerprint)
        })

        when {
            encryption == "none" -> {}
            encryption.startsWith("ss;") -> add("shadowsocks", JsonObject().apply {
                addProperty("enabled", true)
                addProperty("method", encryption.substringAfter(";").substringBefore(":"))
                addProperty("password", encryption.substringAfter(":"))
            })
        }

    })
}
