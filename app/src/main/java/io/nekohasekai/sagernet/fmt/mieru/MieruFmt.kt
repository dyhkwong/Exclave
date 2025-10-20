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

import io.nekohasekai.sagernet.LogLevel
import io.nekohasekai.sagernet.database.DataStore
import io.nekohasekai.sagernet.ktx.queryParameter
import io.nekohasekai.sagernet.ktx.toStringPretty
import libcore.Libcore
import org.json.JSONArray
import org.json.JSONObject

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
        url.queryParameter("handshake-mode")?.let {
            when (it) {
                "HANDSHAKE_STANDARD" -> handshakeMode = MieruBean.HANDSHAKE_STANDARD
                "HANDSHAKE_NO_WAIT" -> handshakeMode = MieruBean.HANDSHAKE_NO_WAIT
            }
        }
    }
}

fun MieruBean.toUri(): String? {
    val builder = Libcore.newURL("mierus").apply {
        host = serverAddress.ifEmpty { error("empty server address") }
    }
    if (username.isNotEmpty()) {
        builder.username = username
    } else {
        error("empty username")
    }
    if (password.isNotEmpty()) {
        builder.password = password
    } else {
        error("empty password")
    }
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
    when (handshakeMode) {
        MieruBean.HANDSHAKE_STANDARD -> {
            builder.addQueryParameter("handshake-mode", "HANDSHAKE_STANDARD")
        }
        MieruBean.HANDSHAKE_NO_WAIT -> {
            builder.addQueryParameter("handshake-mode", "HANDSHAKE_NO_WAIT")
        }
    }
    return builder.string
}

fun MieruBean.buildMieruConfig(port: Int): String {
    return JSONObject().also {
        // Uncomment this means giving up the support for mieru < 3.13, mieru version 2 and mieru version 1.
        /*it.put("advancedSettings", JSONObject().also {
            it.put("noCheckUpdate", true)
        })*/
        it.put("activeProfile", "default")
        it.put("socks5Port", port)
        it.put("loggingLevel", when (DataStore.logLevel) {
            LogLevel.DEBUG -> "TRACE"
            LogLevel.INFO -> "INFO"
            LogLevel.WARNING -> "WARN"
            LogLevel.ERROR -> "ERROR"
            else -> "FATAL"
        })
        it.put("profiles", JSONArray().apply {
            put(JSONObject().also {
                it.put("profileName", "default")
                it.put("user", JSONObject().also {
                    it.put("name", username)
                    it.put("password", password)
                })
                it.put("servers", JSONArray().apply {
                    put(JSONObject().also {
                        it.put("ipAddress", finalAddress)
                        it.put("portBindings", JSONArray().apply {
                            put(JSONObject().also {
                                it.put("port", finalPort)
                                it.put("protocol", when (protocol) {
                                    MieruBean.PROTOCOL_TCP -> "TCP"
                                    MieruBean.PROTOCOL_UDP -> "UDP"
                                    else -> error("unexpected protocol $protocol")
                                })
                            })
                        })
                    })
                })
                if (protocol == MieruBean.PROTOCOL_UDP) {
                    it.put("mtu", mtu)
                }
                if (multiplexingLevel != MieruBean.MULTIPLEXING_DEFAULT) {
                    it.put("multiplexing", JSONObject().also {
                        when (multiplexingLevel) {
                            MieruBean.MULTIPLEXING_OFF -> it.put("level", "MULTIPLEXING_OFF")
                            MieruBean.MULTIPLEXING_LOW -> it.put("level","MULTIPLEXING_LOW")
                            MieruBean.MULTIPLEXING_MIDDLE -> it.put("level", "MULTIPLEXING_MIDDLE")
                            MieruBean.MULTIPLEXING_HIGH -> it.put("level", "MULTIPLEXING_HIGH")
                        }
                    })
                }
                when (handshakeMode) {
                    MieruBean.HANDSHAKE_STANDARD -> it.put("handshakeMode", "HANDSHAKE_STANDARD")
                    MieruBean.HANDSHAKE_NO_WAIT -> it.put("handshakeMode", "HANDSHAKE_NO_WAIT")
                }
            })
        })
    }.toStringPretty()
}
