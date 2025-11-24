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

import io.nekohasekai.sagernet.ktx.listByLineOrComma
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
            } ?: {
                portRange = port
            }
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
        /*url.queryParameter("mtu")?.toIntOrNull()?.let {
            mtu = it
        }*/
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
    if (portRange.isNotEmpty()) {
        builder.addQueryParameter("port", portRange.listByLineOrComma()[0])
    } else {
        builder.addQueryParameter("port", serverPort.toString())
    }
    when (protocol) {
        MieruBean.PROTOCOL_TCP -> {
            builder.addQueryParameter("protocol", "TCP")
        }
        MieruBean.PROTOCOL_UDP -> {
            builder.addQueryParameter("protocol", "UDP")
            /*if (mtu > 0) {
                builder.addQueryParameter("mtu", mtu.toString())
            }*/
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
