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

package io.nekohasekai.sagernet.fmt.socks

import io.nekohasekai.sagernet.ktx.decodeBase64UrlSafe
import io.nekohasekai.sagernet.ktx.queryParameter
import io.nekohasekai.sagernet.ktx.unwrapIDN
import libcore.Libcore

fun parseSOCKS(link: String): SOCKSBean {
    val url = Libcore.parseURL(link)
    if (url.scheme == "socks" && url.port == 0 && url.username.isEmpty() && url.password.isEmpty()) {
        // old v2rayNG format
        // This format is broken if username and/or password contains ":".
        val plainUri = link.removePrefix("socks://").substringBefore("#").decodeBase64UrlSafe()
        return SOCKSBean().apply {
            protocol = SOCKSBean.PROTOCOL_SOCKS5
            serverAddress = plainUri.substringAfterLast("@").substringBeforeLast(":")
                .removeSuffix("/").removePrefix("[").removeSuffix("]").unwrapIDN()
            serverPort = plainUri.substringAfterLast("@").substringAfterLast(":")
                .removeSuffix("/").toIntOrNull()
            username = plainUri.substringBeforeLast("@").substringBefore(":").takeIf { it != "null" } ?: ""
            password = plainUri.substringBeforeLast("@").substringAfter(":").takeIf { it != "null" } ?: ""
            name = url.fragment
        }
    }
    if (url.scheme == "socks" && url.password.isEmpty() && url.username.decodeBase64UrlSafe().contains(":")) {
        // new v2rayNG format
        // This format is broken if username and/or password contains ":".
        return SOCKSBean().apply {
            protocol = SOCKSBean.PROTOCOL_SOCKS5
            serverAddress = url.host.unwrapIDN()
            serverPort = url.port
            username = url.username.decodeBase64UrlSafe().substringBefore(":")
            password = url.username.decodeBase64UrlSafe().substringAfter(":")
            name = url.fragment
        }
    }
    return SOCKSBean().apply {
        protocol = when (url.scheme) {
            "socks4" -> SOCKSBean.PROTOCOL_SOCKS4
            "socks4a" -> SOCKSBean.PROTOCOL_SOCKS4A
            "socks5", "socks5h" /* blame cURL for this */, "socks" -> SOCKSBean.PROTOCOL_SOCKS5
            "socks+tls" -> SOCKSBean.PROTOCOL_SOCKS5 // Who TF invent this?
            else -> error("impossible")
        }
        serverAddress = url.host.unwrapIDN()
        serverPort = url.port.takeIf { it > 0 } ?: 1080
        username = url.username
        password = url.password
        name = url.fragment
        url.queryParameter("tls")?.takeIf { it == "true" || it == "1" }?.let {
            // non-standard
            security = "tls"
            url.queryParameter("sni")?.let {
                sni = it
            }
        }
        if (url.scheme == "socks+tls") {
            // non-standard
            security = "tls"
            url.queryParameter("sni")?.let {
                sni = it
            }
        }
    }
}

fun SOCKSBean.toUri(): String? {
    if (security != "tls" && security != "none") error("unsupported socks with tls")
    if (type != "tcp" || headerType != "none") error("unsupported socks with v2ray transport")

    val builder = Libcore.newURL("socks${protocolVersion()}").apply {
        host = serverAddress.ifEmpty { error("empty server address") }
        port = serverPort
        if (name.isNotEmpty()) fragment = name
    }
    if (username.isNotEmpty()) {
        builder.username = username
    }
    if (password.isNotEmpty()) {
        builder.password = password
    }

    if (security == "tls") {
        // non-standard
        builder.addQueryParameter("tls", "true") // non-standard
        if (sni.isNotEmpty()) {
            builder.addQueryParameter("sni", sni) // non-standard
        }
    }

    return builder.string
}