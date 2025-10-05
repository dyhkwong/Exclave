/******************************************************************************
 *                                                                            *
 * Copyright (C) 2024 by dyhkwong                                             *
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

package io.nekohasekai.sagernet.fmt.juicity

import cn.hutool.core.codec.Base64
import cn.hutool.json.JSONObject
import io.nekohasekai.sagernet.LogLevel
import io.nekohasekai.sagernet.database.DataStore
import io.nekohasekai.sagernet.fmt.LOCALHOST
import io.nekohasekai.sagernet.ktx.*
import libcore.Libcore

// invalid option
val supportedJuicityCongestionControl = arrayOf("cubic", "bbr", "new_reno")

fun parseJuicity(url: String): JuicityBean {
    val link = Libcore.parseURL(url)
    return JuicityBean().apply {
        name = link.fragment
        serverAddress = link.host
        serverPort = link.port
        uuid = link.username
        password = link.password
        link.queryParameter("sni")?.also {
            sni = it
        }
        link.queryParameter("allow_insecure")?.also {
            allowInsecure = (it == "1" || it == "true")
        }
        link.queryParameter("congestion_control")?.also {
            congestionControl = when (it) {
                in supportedJuicityCongestionControl -> it
                else -> "bbr"
            }
        }
        link.queryParameter("pinned_certchain_sha256")?.also {
            when {
                it.length == 64 -> {
                    Base64.encodeUrlSafe(it.chunked(2).map { it.toInt(16).toByte() }.toByteArray())
                }
                else -> {
                    it.replace('/', '_').replace('+', '-')
                }
            }
            pinnedPeerCertificateChainSha256 = it.lowercase()
            // match Juicity's behavior
            // https://github.com/juicity/juicity/blob/412dbe43e091788c5464eb2d6e9c169bdf39f19c/cmd/client/run.go#L97
            allowInsecure = true
        }
    }
}

fun JuicityBean.toUri(): String? {
    val builder = Libcore.newURL("juicity").apply {
        host = serverAddress.ifEmpty { error("empty server address") }
        port = serverPort
        username = uuid.ifEmpty { error("empty uuid") }
        if (name.isNotEmpty()) {
            fragment = name
        }
    }
    if (password.isNotEmpty()) {
        builder.password = password
    }
    builder.addQueryParameter("congestion_control", congestionControl)
    if (sni.isNotEmpty()) {
        builder.addQueryParameter("sni", sni)
    }
    if (pinnedPeerCertificateChainSha256.isNotEmpty()) {
        // https://github.com/juicity/juicity/blob/412dbe43e091788c5464eb2d6e9c169bdf39f19c/cmd/client/run.go#L87-L96
        // it actually supports Base64 URL-safe encoding with padding, Base64 standard encoding with padding and Hex encoding
        val certChainHash = pinnedPeerCertificateChainSha256.listByLineOrComma()[0].replace(":", "")
        builder.addQueryParameter("pinned_certchain_sha256", when {
            certChainHash.length == 64 -> {
                Base64.encodeUrlSafe(certChainHash.chunked(2).map { it.toInt(16).toByte() }.toByteArray())
            }
            else -> {
                certChainHash.replace('/', '_').replace('+', '-').lowercase()
            }
        })
    }
    // as `pinnedPeerCertificate(PublicKey)Sha256` is not exportable,
    // only add `allow_insecure=1` if `pinnedPeerCertificate(PublicKey)Sha256` is not used
    if (pinnedPeerCertificateChainSha256.isNotEmpty() ||
        (allowInsecure && pinnedPeerCertificateSha256.isEmpty() &&
                pinnedPeerCertificatePublicKeySha256.isEmpty())
        ) {
        builder.addQueryParameter("allow_insecure", "1")
    }
    return builder.string
}

fun JuicityBean.buildJuicityConfig(port: Int): String {
    return JSONObject().also {
        it["listen"] = joinHostPort(LOCALHOST, port)
        it["server"] = joinHostPort(finalAddress, finalPort)
        it["uuid"] = uuid
        it["password"] = password
        it["congestion_control"] = congestionControl
        if (sni.isNotEmpty()) {
            it["sni"] = sni
        } else {
            it["sni"] = serverAddress
        }
        if (allowInsecure || pinnedPeerCertificateChainSha256.isNotEmpty()) {
            it["allow_insecure"] = true
        }
        if (pinnedPeerCertificateChainSha256.isNotEmpty()) {
            val certChainHash = pinnedPeerCertificateChainSha256.listByLineOrComma()[0].replace(":", "")
            it["pinned_certchain_sha256"] = when {
                certChainHash.length == 64 -> {
                    Base64.encodeUrlSafe(certChainHash.chunked(2).map { it.toInt(16).toByte() }.toByteArray())
                }
                else -> {
                    certChainHash.replace('/', '_').replace('+', '-')
                }
            }
        }
        it["log_level"] = when (DataStore.logLevel) {
            LogLevel.DEBUG -> "trace"
            LogLevel.INFO -> "info"
            LogLevel.WARNING -> "warn"
            LogLevel.ERROR -> "error"
            else -> "panic"
        }
    }.toStringPretty()
}
