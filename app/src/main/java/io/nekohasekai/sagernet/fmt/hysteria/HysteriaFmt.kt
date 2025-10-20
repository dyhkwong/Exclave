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

package io.nekohasekai.sagernet.fmt.hysteria

import io.nekohasekai.sagernet.database.DataStore
import io.nekohasekai.sagernet.fmt.LOCALHOST
import io.nekohasekai.sagernet.ktx.*
import libcore.Libcore
import org.json.JSONObject
import java.io.File
import kotlin.io.encoding.Base64

val supportedHysteriaProtocol = arrayOf("udp", "faketcp", "wechat-video")

// https://v1.hysteria.network/docs/uri-scheme/
// hysteria://host:port?auth=123456&peer=sni.domain&insecure=1|0&upmbps=100&downmbps=100&alpn=hysteria&obfs=xplus&obfsParam=123456#remarks
fun parseHysteria(url: String): HysteriaBean {
    val link = Libcore.parseURL(url)

    return HysteriaBean().apply {
        serverAddress = link.host
        serverPorts = if (link.port > 0) link.port.toString() else "443"
        name = link.fragment

        link.queryParameter("mport")?.takeIf { it.isValidHysteriaMultiPort() }?.also {
            serverPorts = it
        }
        link.queryParameter("peer")?.also {
            sni = it
        } ?: link.queryParameter("sni")?.also {
            sni = it
        }
        link.queryParameter("auth")?.also {
            authPayloadType = HysteriaBean.TYPE_STRING
            authPayload = it
        }
        link.queryParameter("insecure")?.takeIf { it == "1" || it == "true" }?.also {
            allowInsecure = true
        }
        link.queryParameter("alpn")?.also {
            alpn = it.split(",")[0]
        }
        link.queryParameter("obfs")?.also {
            if (it.isNotEmpty() && it != "xplus") {
                error("unsupport obfs")
            }
            link.queryParameter("obfsParam")?.also {
                obfuscation = it
            }
        }
        link.queryParameter("protocol")?.also {
            protocol = when (it) {
                "" -> HysteriaBean.PROTOCOL_UDP
                !in supportedHysteriaProtocol -> error("unsupported protocol")
                "udp" -> HysteriaBean.PROTOCOL_UDP
                "faketcp" -> HysteriaBean.PROTOCOL_FAKETCP
                "wechat-video" -> HysteriaBean.PROTOCOL_WECHAT_VIDEO
                else -> error("invalid")
            }
        }
        link.queryParameter("upmbps")?.also {
            uploadMbps = it.toLongOrNull()
        }
        link.queryParameter("downmbps")?.also {
            downloadMbps = it.toLongOrNull()
        }
    }
}

fun HysteriaBean.toUri(): String? {
    if (!serverPorts.isValidHysteriaPort()) {
        error("invalid port")
    }

    val builder = Libcore.newURL("hysteria").apply {
        host = serverAddress.ifEmpty { error("empty server address") }
        port = serverPorts.substringBefore(",").substringBefore("-").toInt() // use the first port if port hopping
        if (name.isNotEmpty()) {
            fragment = name
        }
    }

    if (serverPorts.isValidHysteriaMultiPort()) {
        builder.addQueryParameter("mport", serverPorts)
    }
    if (sni.isNotEmpty()) {
        builder.addQueryParameter("peer", sni)
    }
    if (authPayloadType != HysteriaBean.TYPE_NONE && authPayload.isNotEmpty()) {
        when (authPayloadType) {
            HysteriaBean.TYPE_BASE64 -> {
                builder.addQueryParameter("auth", String(Base64.decode(authPayload)))
            }
            HysteriaBean.TYPE_STRING -> {
                builder.addQueryParameter("auth", authPayload)
            }
        }
    }

    if (uploadMbps != 0L) {
        builder.addQueryParameter("upmbps", "$uploadMbps")
    }
    if (downloadMbps != 0L) {
        builder.addQueryParameter("downmbps", "$downloadMbps")
    }
    if (alpn.isNotEmpty()) {
        builder.addQueryParameter("alpn", alpn)
    }
    if (obfuscation.isNotEmpty()) {
        builder.addQueryParameter("obfs", "xplus")
        builder.addQueryParameter("obfsParam", obfuscation)
    }
    when (protocol) {
        HysteriaBean.PROTOCOL_UDP -> {
            builder.addQueryParameter("protocol", "udp")
        }
        HysteriaBean.PROTOCOL_FAKETCP -> {
            builder.addQueryParameter("protocol", "faketcp")
        }
        HysteriaBean.PROTOCOL_WECHAT_VIDEO -> {
            builder.addQueryParameter("protocol", "wechat-video")
        }
    }

    return builder.string
}

fun HysteriaBean.buildHysteriaConfig(port: Int, cacheFile: (() -> File)?): String {
    if (!serverPorts.isValidHysteriaPort()) {
        error("invalid port: $serverPorts")
    }
    val usePortHopping = DataStore.hysteriaEnablePortHopping && serverPorts.isValidHysteriaMultiPort()

    return JSONObject().also {
        if (protocol == HysteriaBean.PROTOCOL_FAKETCP || usePortHopping) {
            // Hysteria port hopping is incompatible with chain proxy
            if (usePortHopping) {
                it.put("server", if (serverAddress.isIpv6Address()) {
                    "[$serverAddress]:$serverPorts"
                } else {
                    "$serverAddress:$serverPorts"
                })
            } else {
                it.put("server", if (serverAddress.isIpv6Address()) {
                    "[" + serverAddress + "]:" + serverPorts.toHysteriaPort()
                } else {
                    serverAddress + ":" + serverPorts.toHysteriaPort()
                })
            }
        } else {
            it.put("server", joinHostPort(finalAddress, finalPort))
        }
        when (protocol) {
            HysteriaBean.PROTOCOL_FAKETCP -> {
                it.put("protocol", "faketcp")
            }
            HysteriaBean.PROTOCOL_WECHAT_VIDEO -> {
                it.put("protocol", "wechat-video")
            }
        }
        it.put("up_mbps", uploadMbps)
        it.put("down_mbps", downloadMbps)
        it.put("socks5", JSONObject(mapOf("listen" to joinHostPort(LOCALHOST, port))))
        if (obfuscation.isNotEmpty()) {
            it.put("obfs", obfuscation)
        }
        when (authPayloadType) {
            HysteriaBean.TYPE_BASE64 -> it.put("auth", authPayload)
            HysteriaBean.TYPE_STRING -> it.put("auth_str", authPayload)
        }
        var servername = sni
        if (!usePortHopping && protocol != HysteriaBean.PROTOCOL_FAKETCP) {
            if (servername.isEmpty()) {
                servername = serverAddress
            }
        }
        if (servername.isNotEmpty()) {
            it.put("server_name", servername)
        }
        if (alpn.isNotEmpty()) it.put("alpn", alpn)
        if (caText.isNotEmpty() && cacheFile != null) {
            val caFile = cacheFile()
            caFile.writeText(caText)
            it.put("ca", caFile.absolutePath)
        }

        if (allowInsecure) it.put("insecure", true)
        if (streamReceiveWindow > 0) it.put("recv_window_conn", streamReceiveWindow)
        if (connectionReceiveWindow > 0) it.put("recv_window", connectionReceiveWindow)
        if (disableMtuDiscovery) it.put("insecure", true)

        it.put("lazy_start", true)
        it.put("fast_open", true)
    }.toStringPretty()
}
