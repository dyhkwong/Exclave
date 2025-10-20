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

import io.nekohasekai.sagernet.LogLevel
import io.nekohasekai.sagernet.database.DataStore
import io.nekohasekai.sagernet.fmt.LOCALHOST
import io.nekohasekai.sagernet.ktx.queryParameter
import io.nekohasekai.sagernet.ktx.toStringPretty
import libcore.Libcore
import org.json.JSONArray
import org.json.JSONObject

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
    return JSONObject().also { conf ->
        conf.put("run_type", "client")
        conf.put("local_addr", LOCALHOST)
        conf.put("local_port", port)
        conf.put("remote_addr", finalAddress)
        conf.put("remote_port", finalPort)
        conf.put("password", JSONArray().apply {
            put(password)
        })
        conf.put("log_level", when (DataStore.logLevel) {
            LogLevel.DEBUG -> 0
            LogLevel.INFO -> 1
            LogLevel.WARNING -> 2
            LogLevel.ERROR -> 3
            else -> 5
        })
        if (mux) conf.put("mux", JSONObject().also {
            it.put("enabled", true)
            it.put("concurrency", muxConcurrency)
        })

        when (type) {
            "ws" -> conf.put("websocket", JSONObject().also {
                it.put("enabled", true)
                it.put("host", host)
                it.put("path", path)
            })
        }

        var servername = sni
        if (servername.isEmpty()) {
            servername = serverAddress
        }

        conf.put("ssl", JSONObject().also {
            if (servername.isNotEmpty()) it.put("sni", servername)
            if (allowInsecure) it.put("verify", false)
            if (utlsFingerprint.isNotEmpty()) it.put("fingerprint", utlsFingerprint)
        })

        when {
            encryption == "none" -> {}
            encryption.startsWith("ss;") -> conf.put("shadowsocks", JSONObject().also {
                it.put("enabled", true)
                it.put("method", encryption.substringAfter(";").substringBefore(":"))
                it.put("password", encryption.substringAfter(":"))
            })
        }

    }.toStringPretty()
}
