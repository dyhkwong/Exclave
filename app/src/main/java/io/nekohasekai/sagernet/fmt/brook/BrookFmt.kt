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

package io.nekohasekai.sagernet.fmt.brook

import io.nekohasekai.sagernet.fmt.AbstractBean
import io.nekohasekai.sagernet.fmt.LOCALHOST
import io.nekohasekai.sagernet.fmt.socks.SOCKSBean
import io.nekohasekai.sagernet.ktx.*
import io.nekohasekai.sagernet.utils.Commandline
import libcore.Libcore

fun parseBrook(text: String): AbstractBean {
    val link = Libcore.parseURL(text)
    val bean = if (link.host == "socks5") SOCKSBean() else BrookBean()
    link.queryParameter("name")?.let {
        bean.name = it
    }
    if (link.host != "socks5") {
        bean as BrookBean
        link.queryParameter("clientHKDFInfo")?.let {
            bean.clientHKDFInfo = it
        }
        link.queryParameter("serverHKDFInfo")?.let {
            bean.serverHKDFInfo = it
        }
        link.queryParameter("token")?.let {
            bean.token = it
        }
    }
    // "Do not omit the port under any circumstances"
    when (link.host) {
        "server" -> {
            bean as BrookBean
            bean.protocol = ""
            link.queryParameter("server")?.let {
                Libcore.parseURL("placeholder://$it")?.apply {
                    bean.serverAddress = host
                    bean.serverPort = port
                } ?: error("Invalid brook server url")
            } ?: error("Invalid brook server url")
            link.queryParameter("password")?.let {
                bean.password = it
            }
            link.queryParameter("udpovertcp")?.let {
                bean.udpovertcp = it == "true"
            }
        }
        "wsserver" -> {
            bean as BrookBean
            bean.protocol = "ws"
            link.queryParameter("wsserver")?.let {
                Libcore.parseURL(it)?.apply {
                    if (scheme != "ws") {
                        error("Invalid brook wsserver url")
                    }
                    bean.serverAddress = host
                    bean.serverPort = port
                    bean.wsPath = path
                } ?: error("Invalid brook wsserver url")
            } ?: error("Invalid brook wsserver url")
            link.queryParameter("address")?.let {
                Libcore.parseURL("placeholder://$it")?.apply {
                    bean.serverAddress = host
                    bean.serverPort = port
                } ?: error("Invalid brook wsserver address")
            }
            link.queryParameter("password")?.let {
                bean.password = it
            }
            link.queryParameter("withoutBrookProtocol")?.let {
                bean.withoutBrookProtocol = it == "true"
            }
        }
        "wssserver" -> {
            bean as BrookBean
            bean.protocol = "wss"
            link.queryParameter("wssserver")?.let {
                Libcore.parseURL(it)?.apply {
                    if (scheme != "wss") {
                        error("Invalid brook wssserver url")
                    }
                    bean.serverAddress = host
                    bean.serverPort = port
                    bean.wsPath = path
                } ?: error("Invalid brook wssserver url")
            } ?: error("Invalid brook wssserver url")
            link.queryParameter("address")?.let {
                bean.sni = bean.serverAddress
                Libcore.parseURL("placeholder://$it")?.apply {
                    bean.serverAddress = host
                    bean.serverPort = port
                } ?: error("Invalid brook wssserver address")
            }
            link.queryParameter("password")?.let {
                bean.password = it
            }
            link.queryParameter("withoutBrookProtocol")?.let {
                bean.withoutBrookProtocol = it == "true"
            }
            link.queryParameter("insecure")?.let {
                bean.insecure = it == "true"
            }
            // link.queryParameter("tlsfingerprint")
            link.queryParameter("fragment")?.let {
                bean.fragment = it
            }
            link.queryParameter("ca")?.let {
                bean.ca = it
            }
        }
        "quicserver" -> {
            bean as BrookBean
            bean.protocol = "quic"
            link.queryParameter("quicserver")?.let {
                Libcore.parseURL(it)?.apply {
                    if (scheme != "quic") {
                        error("Invalid brook quicserver url")
                    }
                    bean.serverAddress = host
                    bean.serverPort = port
                } ?: error("Invalid brook quicserver url")
            } ?: error("Invalid brook quicserver url")
            link.queryParameter("address")?.let {
                bean.sni = bean.serverAddress
                Libcore.parseURL("placeholder://$it")?.apply {
                    bean.serverAddress = host
                    bean.serverPort = port
                } ?: error("Invalid brook quicserver address")
            }
            link.queryParameter("password")?.let {
                bean.password = it
            }
            link.queryParameter("withoutBrookProtocol")?.let {
                bean.withoutBrookProtocol = it == "true"
            }
            link.queryParameter("insecure")?.let {
                bean.insecure = it == "true"
            }
            link.queryParameter("udpoverstream")?.let {
                bean.udpoverstream = it == "true"
            }
            link.queryParameter("ca")?.let {
                bean.ca = it
            }
        }
        "socks5" -> {
            bean as SOCKSBean
            link.queryParameter("socks5")?.let {
                Libcore.parseURL(it)?.apply {
                    if (scheme != "socks5") {
                        error("Invalid brook socks5 url")
                    }
                    bean.serverAddress = host
                    bean.serverPort = port
                } ?: error("Invalid brook socks5 url")
            } ?: error("Invalid brook socks5 url")
            link.queryParameter("username")?.let {
                bean.username = it
            }
            link.queryParameter("password")?.let {
                bean.password = it
            }
        }
        else -> error("invalid")
    }
    return bean
}

fun BrookBean.toUri(): String? {
    val builder = Libcore.newURL("brook")
    if (clientHKDFInfo.isNotEmpty()) {
        builder.addQueryParameter("clientHKDFInfo", clientHKDFInfo)
    }
    if (serverHKDFInfo.isNotEmpty()) {
        builder.addQueryParameter("serverHKDFInfo", serverHKDFInfo)
    }
    if (token.isNotEmpty()) {
        builder.addQueryParameter("token", token)
    }
    when (protocol) {
        "ws" -> {
            builder.host = "wsserver"
            Libcore.newURL("ws").apply {
                host = serverAddress
                port = serverPort
                path = wsPath
            }?.string?.let {
                builder.addQueryParameter("wsserver", it)
            }
            if (withoutBrookProtocol) {
                builder.addQueryParameter("withoutBrookProtocol", "true")
            }
        }
        "wss" -> {
            builder.host = "wssserver"
            Libcore.newURL("wss").apply {
                host = sni.ifEmpty { serverAddress }
                port = serverPort
                path = wsPath
            }?.string?.let {
                builder.addQueryParameter("wssserver", it)
            }
            if (sni.isNotEmpty()) {
                builder.addQueryParameter("address", joinHostPort(serverAddress, serverPort))
            }
            if (withoutBrookProtocol) {
                builder.addQueryParameter("withoutBrookProtocol", "true")
            }
            if (insecure) {
                builder.addQueryParameter("insecure", "true")
            }
            if (tlsfingerprint.isNotEmpty()) {
                builder.addQueryParameter("tlsfingerprint", tlsfingerprint)
            }
            if (fragment.isNotEmpty()) {
                builder.addQueryParameter("fragment", fragment)
            }
            if (ca.isNotEmpty()) {
                builder.addQueryParameter("ca", ca)
            }
        }
        "quic" -> {
            builder.host = "quicserver"
            Libcore.newURL("quic").apply {
                host = sni.ifEmpty { serverAddress }
                port = serverPort
            }?.string?.let {
                builder.addQueryParameter("quicserver", it)
            }
            if (sni.isNotEmpty()) {
                builder.addQueryParameter("address", joinHostPort(serverAddress, serverPort))
            }
            if (withoutBrookProtocol) {
                builder.addQueryParameter("withoutBrookProtocol", "true")
            }
            if (insecure) {
                builder.addQueryParameter("insecure", "true")
            }
            if (udpoverstream) {
                builder.addQueryParameter("udpoverstream", "true")
            }
            if (ca.isNotEmpty()) {
                builder.addQueryParameter("ca", ca)
            }
        }
        else -> {
            builder.host = "server"
            builder.addQueryParameter("server", joinHostPort(serverAddress, serverPort))
            if (udpovertcp) {
                builder.addQueryParameter("udpovertcp", "true")
            }
        }
    }
    if (name.isNotEmpty()) {
        builder.addQueryParameter("password", password)
    }

    if (name.isNotEmpty()) {
        builder.addQueryParameter("name", name)
    }
    return builder.string
}


fun BrookBean.toInternalUri(): String {
    val builder = Libcore.newURL("brook")
    builder.addQueryParameter("password", password)
    if (clientHKDFInfo.isNotEmpty()) {
        builder.addQueryParameter("clientHKDFInfo", clientHKDFInfo)
    }
    if (serverHKDFInfo.isNotEmpty()) {
        builder.addQueryParameter("serverHKDFInfo", serverHKDFInfo)
    }
    if (token.isNotEmpty()) {
        builder.addQueryParameter("token", token)
    }
    when (protocol) {
        "ws" -> {
            builder.host = "wsserver"
            builder.addQueryParameter("wsserver", Libcore.newURL("ws").apply {
                host = finalAddress
                port = finalPort
                if (wsPath.isNotEmpty()) {
                    path = wsPath
                }
            }.string)
            if (withoutBrookProtocol) {
                builder.addQueryParameter("withoutBrookProtocol", "true")
            }
        }
        "wss" -> {
            builder.host = "wssserver"
            builder.addQueryParameter("wssserver", Libcore.newURL("wss").apply {
                host = sni.ifEmpty { serverAddress }
                port = finalPort
                if (wsPath.isNotEmpty()) {
                    path = wsPath
                }
            }.string)
            if (withoutBrookProtocol) {
                builder.addQueryParameter("withoutBrookProtocol", "true")
            }
            if (insecure) {
                builder.addQueryParameter("insecure", "true")
            }
            if (tlsfingerprint.isNotEmpty()) {
                builder.addQueryParameter("tlsfingerprint", tlsfingerprint)
            }
            if (fragment.isNotEmpty()) {
                builder.addQueryParameter("fragment", fragment)
            }
            if (ca.isNotEmpty()) {
                builder.addQueryParameter("ca", ca)
            }
            builder.addQueryParameter("address", joinHostPort(finalAddress, finalPort))
        }
        "quic" -> {
            builder.host = "quicserver"
            builder.addQueryParameter("quicserver", Libcore.newURL("quic").apply {
                host = sni.ifEmpty { serverAddress }
                port = finalPort
            }.string)
            if (withoutBrookProtocol) {
                builder.addQueryParameter("withoutBrookProtocol", "true")
            }
            if (insecure) {
                builder.addQueryParameter("insecure", "true")
            }
            if (udpoverstream) {
                builder.addQueryParameter("udpoverstream", "true")
            }
            if (ca.isNotEmpty()) {
                builder.addQueryParameter("ca", ca)
            }
            builder.addQueryParameter("address", joinHostPort(finalAddress, finalPort))
        }
        else -> {
            builder.host = "server"
            builder.addQueryParameter("server", joinHostPort(finalAddress, finalPort))
            if (udpovertcp) {
                builder.addQueryParameter("udpovertcp", "true")
            }
        }
    }
    return builder.string
}

fun BrookBean.buildBrookConfig(port: Int): String {
    // https://github.com/TxThinkingInc/CAC
    val cac = mutableListOf<String>()
    cac.add(when (protocol) {
        "ws" -> {
            "wsclient"
        }
        "wss" -> {
            "wssclient"
        }
        "quic" -> {
            "quicclient"
        }
        else -> {
            "client"
        }
    })
    cac.add("--link")
    cac.add(toInternalUri())
    cac.add("--socks5")
    cac.add(joinHostPort(LOCALHOST, port))
    return Commandline.toString(cac)
}
