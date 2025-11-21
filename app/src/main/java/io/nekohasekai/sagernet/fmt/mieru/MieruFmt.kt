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

import com.google.gson.GsonBuilder
import com.google.gson.JsonArray
import com.google.gson.JsonObject
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
    return GsonBuilder().setPrettyPrinting().create().toJson(JsonObject().apply {
        // Uncomment this means giving up the support for mieru < 3.13, mieru version 2 and mieru version 1.
        /*add("advancedSettings", JsonObject().apply {
            addProperty("noCheckUpdate", true)
        })*/
        addProperty("activeProfile", "default")
        addProperty("socks5Port", port)
        addProperty("loggingLevel", when (DataStore.logLevel) {
            LogLevel.DEBUG -> "TRACE"
            LogLevel.INFO -> "INFO"
            LogLevel.WARNING -> "WARN"
            LogLevel.ERROR -> "ERROR"
            else -> "FATAL"
        })
        add("profiles", JsonArray().apply {
            add(JsonObject().apply {
                addProperty("profileName", "default")
                add("user", JsonObject().apply {
                    addProperty("name", username)
                    addProperty("password", password)
                })
                add("servers", JsonArray().apply {
                    add(JsonObject().apply {
                        addProperty("ipAddress", finalAddress)
                        add("portBindings", JsonArray().apply {
                            add(JsonObject().apply {
                                addProperty("port", finalPort)
                                addProperty("protocol", when (protocol) {
                                    MieruBean.PROTOCOL_TCP -> "TCP"
                                    MieruBean.PROTOCOL_UDP -> "UDP"
                                    else -> error("unexpected protocol $protocol")
                                })
                            })
                        })
                    })
                })
                if (protocol == MieruBean.PROTOCOL_UDP) {
                    addProperty("mtu", mtu)
                }
                if (multiplexingLevel != MieruBean.MULTIPLEXING_DEFAULT) {
                    add("multiplexing", JsonObject().apply {
                        when (multiplexingLevel) {
                            MieruBean.MULTIPLEXING_OFF -> addProperty("level", "MULTIPLEXING_OFF")
                            MieruBean.MULTIPLEXING_LOW -> addProperty("level","MULTIPLEXING_LOW")
                            MieruBean.MULTIPLEXING_MIDDLE -> addProperty("level", "MULTIPLEXING_MIDDLE")
                            MieruBean.MULTIPLEXING_HIGH -> addProperty("level", "MULTIPLEXING_HIGH")
                        }
                    })
                }
                when (handshakeMode) {
                    MieruBean.HANDSHAKE_STANDARD -> addProperty("handshakeMode", "HANDSHAKE_STANDARD")
                    MieruBean.HANDSHAKE_NO_WAIT -> addProperty("handshakeMode", "HANDSHAKE_NO_WAIT")
                }
            })
        })
    })
}
