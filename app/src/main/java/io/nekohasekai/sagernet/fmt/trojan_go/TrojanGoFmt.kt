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

import cn.hutool.json.JSONArray
import cn.hutool.json.JSONObject
import com.github.shadowsocks.plugin.PluginConfiguration
import com.github.shadowsocks.plugin.PluginManager
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
        link.queryParameter("type")?.let { lType ->
            when (lType) {
                "ws" -> {
                    type = lType
                    link.queryParameter("host")?.let {
                        host = it
                    }
                    link.queryParameter("path")?.let {
                        path = it
                    }
                }
                else -> type = "none"
            }
        }
        link.queryParameter("encryption")?.let {
            encryption = it
        }
        link.queryParameter("plugin")?.let {
            plugin = it
        }
        link.fragment?.let {
            name = it
        }
    }
}

fun TrojanGoBean.toUri(): String {
    val builder = Libcore.newURL("trojan-go")
    builder.host = serverAddress
    builder.port = serverPort
    builder.username = password

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

    if (encryption.isNotEmpty() && encryption != "none") {
        builder.addQueryParameter("encryption", encryption)
    }
    if (plugin.isNotEmpty() && PluginConfiguration(plugin).selected.isNotEmpty()) {
        var p = PluginConfiguration(plugin).selected
        if (PluginConfiguration(plugin).getOptions().toString().isNotEmpty()) {
            p += ";" + PluginConfiguration(plugin).getOptions().toString()
        }
        builder.addQueryParameter("plugin", p)
    }

    if (name.isNotEmpty()) {
        builder.fragment = name
    }

    return builder.string
}

fun TrojanGoBean.buildTrojanGoConfig(port: Int): String {
    return JSONObject().also { conf ->
        conf["run_type"] = "client"
        conf["local_addr"] = LOCALHOST
        conf["local_port"] = port
        conf["remote_addr"] = finalAddress
        conf["remote_port"] = finalPort
        conf["password"] = JSONArray().apply {
            add(password)
        }
        conf["log_level"] = when (DataStore.logLevel) {
            LogLevel.DEBUG -> 0
            LogLevel.INFO -> 1
            LogLevel.WARNING -> 2
            LogLevel.ERROR -> 3
            else -> 5
        }
        if (mux) conf["mux"] = JSONObject().also {
            it["enabled"] = true
            it["concurrency"] = muxConcurrency
        }

        when (type) {
            "ws" -> conf["websocket"] = JSONObject().also {
                it["enabled"] = true
                it["host"] = host
                it["path"] = path
            }
        }

        var servername = sni
        if (servername.isEmpty()) {
            servername = serverAddress
        }

        conf["ssl"] = JSONObject().also {
            if (servername.isNotEmpty()) it["sni"] = servername
            if (allowInsecure) it["verify"] = false
            if (utlsFingerprint.isNotEmpty()) it["fingerprint"] = utlsFingerprint
        }

        when {
            encryption == "none" -> {
            }
            encryption.startsWith("ss;") -> conf["shadowsocks"] = JSONObject().also {
                it["enabled"] = true
                it["method"] = encryption.substringAfter(";").substringBefore(":")
                it["password"] = encryption.substringAfter(":")
            }
        }

        if (plugin.isNotEmpty()) {
            val pluginConfiguration = PluginConfiguration(plugin ?: "")
            PluginManager.init(pluginConfiguration)?.let { (path, opts, _) ->
                conf["transport_plugin"] = JSONObject().also {
                    it["enabled"] = true
                    it["type"] = "shadowsocks"
                    it["command"] = path
                    it["option"] = opts.toString()
                }
            }
        }
    }.toStringPretty()
}
