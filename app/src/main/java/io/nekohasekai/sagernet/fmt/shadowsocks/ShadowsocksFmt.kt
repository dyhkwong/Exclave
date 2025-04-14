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

package io.nekohasekai.sagernet.fmt.shadowsocks

import cn.hutool.core.codec.Base64
import cn.hutool.json.JSONObject
import com.github.shadowsocks.plugin.PluginConfiguration
import com.github.shadowsocks.plugin.PluginOptions
import io.nekohasekai.sagernet.ktx.decodeBase64UrlSafe
import io.nekohasekai.sagernet.ktx.queryParameter
import libcore.Libcore

fun PluginConfiguration.fixInvalidParams() {
    if (selected == "simple-obfs") {
        pluginsOptions["obfs-local"] = getOptions().apply { id = "obfs-local" }
        pluginsOptions.remove(selected)
        selected = "obfs-local"
    }
}

fun ShadowsocksBean.fixInvalidParams() {
    if (method == "plain") method = "none"
    if (!plugin.isNullOrEmpty()) {
        plugin = PluginConfiguration(plugin).apply { fixInvalidParams() }.toString()
    }
}

fun parseShadowsocks(url: String): ShadowsocksBean {
    val link = Libcore.parseURL(url)
    if (link.port == 0 && link.username.isEmpty() && link.password.isEmpty()) {
        // pre-SIP002
        val link1 = Libcore.parseURL("ss://" + link.host.decodeBase64UrlSafe())
        return ShadowsocksBean().apply {
            serverAddress = link1.host
            serverPort = link1.port
            method = link1.username
            password = link1.password
            name = link.fragment
            fixInvalidParams()
        }
    } else {
        // SIP002
        if (link.password.isNotEmpty() ||
            url.substringAfter("ss://").substringBefore("#").substringBefore("@").endsWith(":")) {
            return ShadowsocksBean().apply {
                serverAddress = link.host
                serverPort = link.port
                method = link.username
                password = link.password
                plugin = link.queryParameter("plugin")
                name = link.fragment
                fixInvalidParams()
            }
        }
        return ShadowsocksBean().apply {
            serverAddress = link.host
            serverPort = link.port
            method = link.username.decodeBase64UrlSafe().substringBefore(":")
            password = link.username.decodeBase64UrlSafe().substringAfter(":")
            plugin = link.queryParameter("plugin")
            name = link.fragment
            fixInvalidParams()
        }
    }
}

fun ShadowsocksBean.toUri(): String {
    val builder = Libcore.newURL("ss")
    builder.host = serverAddress
    builder.port = serverPort
    if (method.startsWith("2022-blake3-")) {
        builder.username = method
        builder.password = password
    } else {
        builder.username = Base64.encodeUrlSafe("$method:$password")
    }

    if (plugin.isNotEmpty() && PluginConfiguration(plugin).selected.isNotEmpty()) {
        var p = PluginConfiguration(plugin).selected
        if (PluginConfiguration(plugin).getOptions().toString().isNotEmpty()) {
            p += ";" + PluginConfiguration(plugin).getOptions().toString()
        }
        builder.rawPath = "/"
        builder.addQueryParameter("plugin", p)
    }

    if (name.isNotEmpty()) {
        builder.fragment = name
    }

    return builder.string

}

fun JSONObject.parseShadowsocks(): ShadowsocksBean {
    return ShadowsocksBean().apply {
        var pluginStr = ""
        val pId = getStr("plugin")
        if (!pId.isNullOrEmpty()) {
            val plugin = PluginOptions(pId, getStr("plugin_opts"))
            pluginStr = plugin.toString(false)
        }

        serverAddress = getStr("server")
        serverPort = getInt("server_port")
        password = getStr("password")
        method = getStr("method")
        plugin = pluginStr
        name = getStr("remarks", "")

        fixInvalidParams()
    }
}
