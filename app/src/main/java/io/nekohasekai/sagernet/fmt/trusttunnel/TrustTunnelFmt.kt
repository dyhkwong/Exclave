/******************************************************************************
 *                                                                            *
 * Copyright (C) 2026  dyhkwong                                               *
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
 * along with this program. If not, see <https://www.gnu.org/licenses/>.      *
 *                                                                            *
 ******************************************************************************/

package io.nekohasekai.sagernet.fmt.trusttunnel

import libcore.Libcore

fun TrustTunnelBean.toUri(): String {
    val scheme = when (protocol) {
        "https", "quic" -> protocol
        else -> error("invalid")
    }
    val builder = Libcore.newURL(scheme).apply {
        host = serverAddress.ifEmpty { error("empty server address") }
        port = serverPort
        if (name.isNotEmpty()) {
            fragment = name
        }
    }
    if (username.isNotEmpty()) {
        builder.username = username
    }
    if (password.isNotEmpty()) {
        builder.password = password
    }
    if (sni.isNotEmpty()) {
        // non-standard
        builder.addQueryParameter("sni", sni)
    }

    return builder.string
}