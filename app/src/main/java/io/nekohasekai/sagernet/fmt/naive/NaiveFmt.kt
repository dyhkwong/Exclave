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

package io.nekohasekai.sagernet.fmt.naive

import cn.hutool.json.JSONObject
import io.nekohasekai.sagernet.LogLevel
import io.nekohasekai.sagernet.database.DataStore
import io.nekohasekai.sagernet.fmt.LOCALHOST
import io.nekohasekai.sagernet.ktx.joinHostPort
import io.nekohasekai.sagernet.ktx.listByLine
import io.nekohasekai.sagernet.ktx.queryParameter
import libcore.Libcore

fun parseNaive(link: String): NaiveBean {
    // This format may be https://github.com/klzgrad/naiveproxy/issues/86.
    val url = Libcore.parseURL(link)
    return NaiveBean().apply {
        proto = when (url.scheme) {
            "naive+https" -> "https"
            "naive+quic" -> "quic"
            else -> error("impossible")
        }
        serverAddress = url.host
        serverPort = url.port.takeIf { it > 0 } ?: 443
        username = url.username
        password = url.password
        sni = url.queryParameter("sni")
        extraHeaders = url.queryParameter("extra-headers")?.replace("\r\n", "\n")
        insecureConcurrency = url.queryParameter("insecure-concurrency")?.toIntOrNull()
        name = url.fragment
        initializeDefaultValues()
    }
}

fun NaiveBean.toUri(proxyOnly: Boolean = false): String {
    val builder = Libcore.newURL(if (proxyOnly) proto else "naive+$proto")
    if (sni.isNotEmpty() && proxyOnly) {
        builder.host = sni
    } else {
        builder.host = serverAddress
    }
    if (proxyOnly && canMapping()) {
        builder.port = finalPort
    } else {
        builder.port = serverPort
    }
    if (username.isNotEmpty()) {
        builder.username = username
    }
    if (password.isNotEmpty()) {
        builder.password = password
    }
    if (!proxyOnly) {
        if (extraHeaders.isNotEmpty()) {
            builder.addQueryParameter("extra-headers", extraHeaders.listByLine().joinToString("\r\n"))
        }
        if (name.isNotEmpty()) {
            builder.fragment = name
        }
        if (insecureConcurrency > 0) {
            builder.addQueryParameter("insecure-concurrency", "$insecureConcurrency")
        }
        if (sni.isNotEmpty()) {
            builder.addQueryParameter("sni", sni)
        }
    }
    return builder.string
}

fun NaiveBean.buildNaiveConfig(port: Int): String {
    return JSONObject().also {
        it["listen"] = "socks://" + joinHostPort(LOCALHOST, port)
        // NaïveProxy v130.0.6723.40-2 release notes:
        // Fixed a crash when the username or password contains the comma character `,`.
        // The comma is used for delimiting proxies in a proxy chain.
        // It must be percent-encoded in other URL components.
        it["proxy"] = toUri(true).replace(",", "%2C")
        if (extraHeaders.isNotEmpty()) {
            it["extra-headers"] = extraHeaders.listByLine().joinToString("\r\n")
        }
        if (sni.isNotEmpty()) {
            it["host-resolver-rules"] = "MAP $sni $finalAddress"
        } else {
            it["host-resolver-rules"] = "MAP $serverAddress $finalAddress"
        }
        if (DataStore.logLevel != LogLevel.NONE) {
            it["log"] = ""
        }
        if (insecureConcurrency > 0) {
            it["insecure-concurrency"] = insecureConcurrency
        }
        if (noPostQuantum) {
            it["no-post-quantum"] = true
        }
    }.toStringPretty()
}