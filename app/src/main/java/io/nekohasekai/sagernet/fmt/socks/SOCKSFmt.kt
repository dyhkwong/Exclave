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
import libcore.Libcore

fun parseSOCKS(link: String): SOCKSBean {
    val url = Libcore.parseURL(link)
    if (url.port == 0 && url.username.isEmpty() && url.password.isEmpty() &&
        url.host.decodeBase64UrlSafe().contains(":")) {
        // v2rayN shit format
        val url1 = Libcore.parseURL("socks://" + url.host.decodeBase64UrlSafe())
        return SOCKSBean().apply {
            serverAddress = url1.host
            serverPort = url1.port
            username = url1.username.takeIf { it != "null" } ?: ""
            password = url1.password.takeIf { it != "null" } ?: ""
            name = url.fragment
        }
    } else if (url.password.isEmpty() && url.username.decodeBase64UrlSafe().contains(":")) {
        // new v2rayNG format?
        return SOCKSBean().apply {
            serverAddress = url.host
            serverPort = url.port
            username = url.username.decodeBase64UrlSafe().substringBefore(":")
            password = url.username.decodeBase64UrlSafe().substringAfter(":")
            name = url.fragment
        }
    } else {
        return SOCKSBean().apply {
            protocol = when {
                link.startsWith("socks4://") -> SOCKSBean.PROTOCOL_SOCKS4
                link.startsWith("socks4a://") -> SOCKSBean.PROTOCOL_SOCKS4A
                else -> SOCKSBean.PROTOCOL_SOCKS5
            }
            serverAddress = url.host
            serverPort = url.port.takeIf { it > 0 } ?: 1080
            username = url.username
            password = url.password
            name = url.fragment
            url.queryParameter("tls")?.takeIf { it == "true" || it == "1" }?.let {
                // non-standard
                url.queryParameter("sni")?.let {
                    sni = it
                }
            }
        }
    }
}

fun SOCKSBean.toUri(): String {
    val builder = Libcore.newURL("socks${protocolVersion()}")
    builder.host = serverAddress
    builder.port = serverPort
    if (!username.isNullOrEmpty()) builder.username = username
    if (!password.isNullOrEmpty()) builder.password = password
    if (security == "tls") {
        // non-standard
        builder.addQueryParameter("tls", "true") // non-standard
        if (sni.isNotEmpty()) {
            builder.addQueryParameter("sni", sni) // non-standard
        }
    }
    if (!name.isNullOrEmpty()) builder.fragment = name
    return builder.string

}