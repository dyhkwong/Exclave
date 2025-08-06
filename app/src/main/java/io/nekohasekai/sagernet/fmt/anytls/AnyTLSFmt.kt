/******************************************************************************
 *                                                                            *
 * Copyright (C) 2025 by dyhkwong                                             *
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

package io.nekohasekai.sagernet.fmt.anytls

import io.nekohasekai.sagernet.ktx.*
import libcore.Libcore

fun parseAnyTLS(url: String): AnyTLSBean {
    val link = Libcore.parseURL(url)
    return AnyTLSBean().apply {
        name = link.fragment
        serverAddress = link.host
        serverPort = link.port.takeIf { it > 0 } ?: 443
        password = link.username
        security = "tls"
        link.queryParameter("sni")?.also {
            sni = it
        }
        link.queryParameter("insecure")?.takeIf { it == "1" }?.also {
            allowInsecure = true
        }
    }
}

fun AnyTLSBean.toUri(): String? {
    if (security != "tls") {
        error("anytls must use tls")
    }
    val builder = Libcore.newURL("anytls")
    builder.host = serverAddress.ifEmpty { error("empty server address") }
    builder.port = serverPort
    if (password.isNotEmpty()) {
        builder.username = password
    }
    builder.rawPath = "/"
    if (sni.isNotEmpty()) {
        builder.addQueryParameter("sni", sni)
    }
    if (allowInsecure) {
        builder.addQueryParameter("insecure", "1")
    }
    if (name.isNotEmpty()) {
        builder.fragment = name
    }
    return builder.string
}
