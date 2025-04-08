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

package io.nekohasekai.sagernet.fmt.mieru

import cn.hutool.json.JSONArray
import cn.hutool.json.JSONObject
import io.nekohasekai.sagernet.LogLevel
import io.nekohasekai.sagernet.database.DataStore
import io.nekohasekai.sagernet.ktx.queryParameter
import libcore.Libcore

fun parseMieru(link: String): MieruBean {
    val url = Libcore.parseURL(link)
    return MieruBean().apply {
        serverAddress = url.host
        username = url.username
        password = url.password
        url.queryParameter("profile")?.let {
            name = it
        }
        url.queryParameter("port")?.let { port ->
            // There can be multiple queries named `port`, which is not so standard,
            // just let the URL library pick one for now.
            port.toIntOrNull()?.let {
                serverPort = it
            } ?: port.substringBefore("-").toIntOrNull()?.let {
                // Multi port format, use the first port only for now.
                serverPort = it
            } ?: error("unknown port: $port")
        } ?: error("no port specified")
        url.queryParameter("protocol")?.let {
            // There can be multiple queries named `protocol`,
            // just let the URL library pick one for now.
            protocol = when (it) {
                "UDP" -> MieruBean.PROTOCOL_UDP
                "TCP" -> MieruBean.PROTOCOL_TCP
                else -> error("unknown protocol: $it")
            }
        } ?: error("no protocol specified")
        url.queryParameter("mtu")?.toIntOrNull()?.let {
            mtu = it
        }
        url.queryParameter("multiplexing")?.let {
            when (it) {
                "MULTIPLEXING_OFF" -> multiplexingLevel = MieruBean.MULTIPLEXING_OFF
                "MULTIPLEXING_LOW" -> multiplexingLevel = MieruBean.MULTIPLEXING_LOW
                "MULTIPLEXING_MIDDLE" -> multiplexingLevel = MieruBean.MULTIPLEXING_MIDDLE
                "MULTIPLEXING_HIGH" -> multiplexingLevel = MieruBean.MULTIPLEXING_HIGH
            }
        }
    }
}

fun MieruBean.toUri(): String {
    val builder = Libcore.newURL("mierus").apply {
        host = serverAddress
    }
    builder.username = username
    builder.password = password
    if (name.isNotEmpty()) {
        builder.addQueryParameter("profile", name)
    }
    builder.addQueryParameter("port", serverPort.toString())
    when (protocol) {
        MieruBean.PROTOCOL_TCP -> {
            builder.addQueryParameter("protocol", "TCP")
        }
        MieruBean.PROTOCOL_UDP -> {
            builder.addQueryParameter("protocol", "UDP")
            if (mtu > 0) {
                builder.addQueryParameter("mtu", mtu.toString())
            }
        }
    }
    when (multiplexingLevel) {
        MieruBean.MULTIPLEXING_OFF -> {
            builder.addQueryParameter("multiplexing", "MULTIPLEXING_OFF")
        }
        MieruBean.MULTIPLEXING_LOW -> {
            builder.addQueryParameter("multiplexing", "MULTIPLEXING_LOW")
        }
        MieruBean.MULTIPLEXING_MIDDLE -> {
            builder.addQueryParameter("multiplexing", "MULTIPLEXING_MIDDLE")
        }
        MieruBean.MULTIPLEXING_HIGH -> {
            builder.addQueryParameter("multiplexing", "MULTIPLEXING_HIGH")
        }
    }
    return builder.string
}

fun MieruBean.buildMieruConfig(port: Int): String {
    return JSONObject().also {
        it["activeProfile"] = "default"
        it["socks5Port"] = port
        it["loggingLevel"] = when (DataStore.logLevel) {
            LogLevel.DEBUG -> "TRACE"
            LogLevel.INFO -> "INFO"
            LogLevel.WARNING -> "WARN"
            LogLevel.ERROR -> "ERROR"
            else -> "FATAL"
        }
        it["profiles"] = JSONArray().apply {
            put(JSONObject().also {
                it["profileName"] = "default"
                it["user"] = JSONObject().also {
                    it["name"] = username
                    it["password"] = password
                }
                it["servers"] = JSONArray().apply {
                    put(JSONObject().also {
                        it["ipAddress"] = finalAddress
                        it["portBindings"] = JSONArray().apply {
                            put(JSONObject().also {
                                it["port"] = finalPort
                                it["protocol"] = when (protocol) {
                                    MieruBean.PROTOCOL_TCP -> "TCP"
                                    MieruBean.PROTOCOL_UDP -> "UDP"
                                    else -> error("unexpected protocol $protocol")
                                }
                            })
                        }
                    })
                }
                if (protocol == MieruBean.PROTOCOL_UDP) {
                    it["mtu"] = mtu
                }
                if (multiplexingLevel != MieruBean.MULTIPLEXING_DEFAULT) {
                    it["multiplexing"] = JSONObject().also {
                        when (multiplexingLevel) {
                            MieruBean.MULTIPLEXING_OFF -> it["level"] = "MULTIPLEXING_OFF"
                            MieruBean.MULTIPLEXING_LOW -> it["level"] = "MULTIPLEXING_LOW"
                            MieruBean.MULTIPLEXING_MIDDLE -> it["level"] = "MULTIPLEXING_MIDDLE"
                            MieruBean.MULTIPLEXING_HIGH -> it["level"] = "MULTIPLEXING_HIGH"
                        }
                    }
                }
            })
        }
    }.toStringPretty()
}
