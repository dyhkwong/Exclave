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

package io.nekohasekai.sagernet.fmt.v2ray

import cn.hutool.json.JSONObject
import io.nekohasekai.sagernet.fmt.trojan.TrojanBean
import io.nekohasekai.sagernet.ktx.*
import libcore.Libcore

fun parseV2Ray(link: String): StandardV2RayBean {
    if (link.startsWith("vmess://") && !link.contains("@")) {
        return parseV2RayN(link)
    }

    val url = Libcore.parseURL(link)
    val bean = when (url.scheme) {
        "vmess" -> VMessBean()
        "vless" -> VLESSBean()
        "trojan" -> TrojanBean()
        else -> error("impossible")
    }

    bean.serverAddress = url.host
    bean.serverPort = url.port
    bean.name = url.fragment

    if (bean is VMessBean && url.password.isNotEmpty()) {
        // https://github.com/v2fly/v2fly-github-io/issues/26
        var protocol = url.username
        bean.type = protocol
        bean.alterId = url.password.substringAfterLast('-').toInt()
        bean.uuid = url.password.substringBeforeLast('-')

        if (protocol.endsWith("+tls")) {
            bean.security = "tls"
            protocol = protocol.substring(0, protocol.length - 4)

            url.queryParameter("tlsServerName")?.let {
                bean.sni = it
            }
        }

        when (protocol) {
            "tcp" -> {
                url.queryParameter("type")?.let { type ->
                    if (type == "http") {
                        bean.headerType = "http"
                        url.queryParameter("host")?.let {
                            bean.host = it
                        }
                    }
                }
            }
            "http" -> {
                url.queryParameter("path")?.let {
                    bean.path = it
                }
                url.queryParameter("host")?.let {
                    bean.host = it.split("|").joinToString(",")
                }
            }
            "ws" -> {
                url.queryParameter("path")?.let {
                    bean.path = it
                }
                url.queryParameter("host")?.let {
                    bean.host = it
                }
            }
            "kcp" -> {
                url.queryParameter("type")?.let {
                    bean.headerType = it
                }
                url.queryParameter("seed")?.let {
                    bean.mKcpSeed = it
                }
            }
            "quic" -> {
                url.queryParameter("security")?.let {
                    bean.quicSecurity = it
                }
                url.queryParameter("key")?.let {
                    bean.quicKey = it
                }
                url.queryParameter("type")?.let {
                    bean.headerType = it
                }
            }
            else -> error("unknown protocol: $protocol")
        }
    } else {
        // https://github.com/XTLS/Xray-core/issues/91
        // https://github.com/XTLS/Xray-core/discussions/716

        if (bean is TrojanBean) {
            // https://github.com/trojan-gfw/igniter/issues/318
            when {
                url.username.isEmpty() && url.password.isEmpty() -> {
                    if (link.substringAfter("trojan://").substringBefore("@") == ":") {
                        bean.password = ":"
                    }
                }
                url.username.isNotEmpty() && url.password.isEmpty() -> {
                    bean.password = if (link.substringAfter("trojan://").substringBefore("@").endsWith(":")) {
                        url.username + ":"
                    } else {
                        url.username
                    }
                }
                url.username.isEmpty() && url.password.isNotEmpty() -> {
                    bean.password = ":" + url.password
                }
                url.username.isNotEmpty() && url.password.isNotEmpty() -> {
                    bean.password = url.username + ":" + url.password
                }
            }
        } else {
            bean.uuid = url.username
        }

        if (bean is VMessBean) {
            bean.encryption = url.queryParameter("encryption")
        }

        bean.type = url.queryParameter("type")

        if (bean is TrojanBean) {
            bean.security = url.queryParameter("security") ?: "tls"
        } else {
            bean.security = url.queryParameter("security") ?: "none"
        }
        when (bean.security) {
            "tls", "xtls" -> {
                bean.security = "tls"
                if (bean is TrojanBean) {
                    bean.sni = url.queryParameter("sni") ?: url.queryParameter("peer")
                } else {
                    url.queryParameter("sni")?.let {
                        bean.sni = it
                    }
                }
                url.queryParameter("alpn")?.let {
                    bean.alpn = it.split(",").joinToString("\n")
                }
                if (bean is VLESSBean && bean.security == "tls") {
                    url.queryParameter("flow")?.let {
                        when (it) {
                            "xtls-rprx-vision", "xtls-rprx-vision-udp443" -> {
                                bean.flow = "xtls-rprx-vision-udp443"
                                bean.packetEncoding = "xudp"
                            }
                        }
                    }
                }
                // bad format from where?
                url.queryParameter("allowInsecure")?.let {
                    if (it == "1" || it.lowercase() == "true") {
                        bean.allowInsecure = true // non-standard
                    }
                } ?: url.queryParameter("insecure")?.let {
                    if (it == "1" || it.lowercase() == "true") {
                        bean.allowInsecure = true // non-standard
                    }
                }
                //url.queryParameter("fp")?.let {} // do not support this intentionally
            }
            "reality" -> {
                url.queryParameter("sni")?.let {
                    bean.sni = it
                }
                url.queryParameter("pbk")?.let {
                    bean.realityPublicKey = it
                }
                url.queryParameter("sid")?.let {
                    bean.realityShortId = it
                }
                url.queryParameter("fp")?.let {
                    bean.realityFingerprint = it
                }
                if (bean is VLESSBean) {
                    url.queryParameter("flow")?.let {
                        when (it) {
                            "xtls-rprx-vision", "xtls-rprx-vision-udp443" -> {
                                bean.flow = "xtls-rprx-vision-udp443"
                                bean.packetEncoding = "xudp"
                            }
                        }
                    }
                }
            }
            else -> bean.security = "none"
        }
        when (bean.type) {
            "tcp" -> {
                url.queryParameter("headerType")?.let { headerType ->
                    // invented by v2rayN(G)
                    if (headerType == "http") {
                        bean.headerType = headerType
                        url.queryParameter("host")?.let {
                            bean.host = it.split(",").joinToString("\n")
                        }
                    }
                }
            }
            "kcp" -> {
                url.queryParameter("headerType")?.let {
                    bean.headerType = it
                }
                url.queryParameter("seed")?.let {
                    bean.mKcpSeed = it
                }
            }
            "http" -> {
                url.queryParameter("host")?.let {
                    // The proposal says "省略时复用 remote-host", but this is not correct except for the breaking change below.
                    // will not follow the breaking change in https://github.com/XTLS/Xray-core/commit/0a252ac15d34e7c23a1d3807a89bfca51cbb559b
                    // "若有多个域名，可使用英文逗号隔开，但中间及前后不可有空格。"
                    bean.host = it.split(",").joinToString("\n")
                }
                url.queryParameter("path")?.let {
                    bean.path = it
                }
            }
            "xhttp", "splithttp" -> {
                bean.type = "splithttp"
                url.queryParameter("extra")?.let { extra ->
                    JSONObject(extra).takeIf { !it.isEmpty() }?.also {
                        // fuck RPRX `extra`
                        bean.splithttpExtra = it.toString()
                    }
                }
                url.queryParameter("host")?.let {
                    bean.host = it
                }
                url.queryParameter("path")?.let {
                    bean.path = it
                }
                when (val mode = url.queryParameter("mode")) {
                    "", "auto" -> bean.splithttpMode = "auto"
                    else -> bean.splithttpMode = mode
                }
            }
            "httpupgrade" -> {
                url.queryParameter("host")?.let {
                    // will not follow the breaking change in
                    // https://github.com/XTLS/Xray-core/commit/a2b773135a860f63e990874c551b099dfc888471
                    bean.host = it
                }
                url.queryParameter("path")?.let { path ->
                    // RPRX's smart-assed invention. This of course will break under some conditions.
                    bean.path = path
                    val u = Libcore.parseURL(path)
                    u.queryParameter("ed")?.let {
                        u.deleteQueryParameter("ed")
                        bean.path = u.string
                    }
                }
                url.queryParameter("eh")?.let {
                    bean.earlyDataHeaderName = it // non-standard, invented by SagerNet and adopted by some other software
                }
                url.queryParameter("ed")?.toIntOrNull()?.let {
                    bean.maxEarlyData = it // non-standard, invented by SagerNet and adopted by some other software
                }
            }
            "ws" -> {
                url.queryParameter("host")?.let {
                    // will not follow the breaking change in
                    // https://github.com/XTLS/Xray-core/commit/a2b773135a860f63e990874c551b099dfc888471
                    bean.host = it
                }
                url.queryParameter("path")?.let { path ->
                    // RPRX's smart-assed invention. This of course will break under some conditions.
                    bean.path = path
                    val u = Libcore.parseURL(path)
                    u.queryParameter("ed")?.let { ed ->
                        u.deleteQueryParameter("ed")
                        bean.path = u.string
                        bean.maxEarlyData = ed.toIntOrNull()
                        bean.earlyDataHeaderName = "Sec-WebSocket-Protocol"
                    }
                }
                url.queryParameter("eh")?.let {
                    bean.earlyDataHeaderName = it // non-standard, invented by SagerNet and adopted by some other software
                }
                url.queryParameter("ed")?.toIntOrNull()?.let {
                    bean.maxEarlyData = it // non-standard, invented by SagerNet and adopted by some other software
                }
            }
            "quic" -> {
                url.queryParameter("headerType")?.let {
                    bean.headerType = it
                }
                url.queryParameter("quicSecurity")?.let { quicSecurity ->
                    bean.quicSecurity = quicSecurity
                    url.queryParameter("key")?.let {
                        bean.quicKey = it
                    }
                }
            }
            "grpc" -> {
                url.queryParameter("serviceName")?.let {
                    // Xray hijacks the share link standard, uses escaped `serviceName` and some other non-standard `serviceName`s and breaks the compatibility with other implementations.
                    // Fixing the compatibility with Xray will break the compatibility with V2Ray and others.
                    // So do not fix the compatibility with Xray.
                    bean.grpcServiceName = it
                }
            }
            "meek" -> {
                // https://github.com/v2fly/v2ray-core/discussions/2638
                url.queryParameter("url")?.let {
                    bean.meekUrl = it
                }
            }
            "mekya" -> {
                // not a standard
                url.queryParameter("headerType")?.let {
                    bean.mekyaKcpHeaderType = it
                }
                url.queryParameter("seed")?.let {
                    bean.mekyaKcpSeed = it
                }
                url.queryParameter("url")?.let {
                    bean.mekyaUrl = it
                }
            }
            "hysteria2" -> error("unsupported")
            else -> bean.type = "tcp"
        }

    }

    return bean
}

fun parseV2RayN(link: String): VMessBean {
    // https://github.com/2dust/v2rayN/wiki/%E5%88%86%E4%BA%AB%E9%93%BE%E6%8E%A5%E6%A0%BC%E5%BC%8F%E8%AF%B4%E6%98%8E(ver-2)
    val result = link.substringAfter("vmess://").decodeBase64UrlSafe()
    if (result.contains("= vmess")) {
        return parseCsvVMess(result)
    }
    val bean = VMessBean()
    val json = JSONObject(result)

    bean.serverAddress = json.getStr("add")?.takeIf { it.isNotEmpty() }
    bean.serverPort = json.getInt("port")
    bean.encryption = json.getStr("scy")?.takeIf { it.isNotEmpty() }
    bean.uuid = json.getStr("id")?.takeIf { it.isNotEmpty() }
    bean.alterId = json.getInt("aid")?.takeIf { it > 0 }
    bean.type = when (val net = json.getStr("net")) {
        "h2" -> "http"
        "xhttp" -> "splithttp"
        "tcp", "kcp", "ws", "http", "quic", "grpc", "httpupgrade", "splithttp" -> net
        else -> "tcp"
    }
    val type = json.getStr("type")?.takeIf { it.isNotEmpty() }
    val host = json.getStr("host")?.takeIf { it.isNotEmpty() }
    val path = json.getStr("path")?.takeIf { it.isNotEmpty() }

    when (bean.type) {
        "tcp" -> {
            bean.host = host?.split(",")?.joinToString("\n") // "http(tcp)->host中间逗号(,)隔开"
            bean.path = path?.split(",")?.joinToString("\n") // see v2rayN(G) source code
            type?.also {
                bean.headerType = type
            }
        }
        "kcp" -> {
            bean.mKcpSeed = path
            type?.also {
                bean.headerType = type
            }
        }
        "ws" -> {
            bean.host = host
            bean.path = path
            // RPRX's smart-assed invention. This of course will break under some conditions.
            val u = Libcore.parseURL(bean.path)
            u.queryParameter("ed")?.let { ed ->
                u.deleteQueryParameter("ed")
                bean.path = u.string
                bean.maxEarlyData = ed.toIntOrNull()
                bean.earlyDataHeaderName = "Sec-WebSocket-Protocol"
            }
        }
        "httpupgrade" -> {
            bean.host = host
            bean.path = path
            // RPRX's smart-assed invention. This of course will break under some conditions.
            val u = Libcore.parseURL(bean.path)
            u.queryParameter("ed")?.let {
                u.deleteQueryParameter("ed")
                bean.path = u.string
            }
        }
        "http" -> {
            bean.host = host?.split(",")?.joinToString("\n") // "http(tcp)->host中间逗号(,)隔开"
            bean.path = path
        }
        "quic" -> {
            bean.quicSecurity = host
            bean.quicKey = path
            type?.also {
                bean.headerType = type
            }
        }
        "grpc" -> {
            // Xray hijacks the share link standard, uses escaped `serviceName` and some other non-standard `serviceName`s and breaks the compatibility with other implementations.
            // Fixing the compatibility with Xray will break the compatibility with V2Ray and others.
            // So do not fix the compatibility with Xray.
            bean.grpcServiceName = bean.path
        }
        "splithttp" -> {
            bean.host = host
            bean.path = path
            type?.also {
                if (it.isNotEmpty() && it != "auto") {
                    bean.splithttpMode = type
                }
            }
        }
    }

    bean.name = json.getStr("ps")?.takeIf { it.isNotEmpty() }
    bean.sni = json.getStr("sni")?.takeIf { it.isNotEmpty() } ?: bean.host
    bean.alpn = json.getStr("alpn")?.takeIf { it.isNotEmpty() }?.split(",")?.joinToString("\n")
    // bad format from where?
    json.getStr("allowInsecure")?.let { // Boolean or Int or String
        if (it == "1" || it.lowercase() == "true") {
            bean.allowInsecure = true // non-standard
        }
    } ?: json.getStr("insecure")?.let { // Boolean or Int or String
        if (it == "1" || it.lowercase() == "true") {
            bean.allowInsecure = true // non-standard
        }
    }
    when (val security = json.getStr("tls")) {
        "tls", "reality" -> bean.security = security
        else -> bean.security = "none"
    }
    bean.realityFingerprint = json.getStr("fp")?.takeIf { it.isNotEmpty() }
    // bean.utlsFingerprint = ? // do not support this intentionally

    // https://github.com/2dust/v2rayN/blob/737d563ebb66d44504c3a9f51b7dcbb382991dfd/v2rayN/v2rayN/Handler/ConfigHandler.cs#L701-L743
    if (json.getStr("v").isNullOrEmpty() || json.getStr("v").toInt() < 2) {
        when (bean.type) {
            "ws", "h2" -> {
                bean.host?.replace(" ", "")?.split(";")?.let {
                    if (it.isNotEmpty()) {
                        bean.path = it[0]
                        bean.host = ""
                    }
                    if (it.size > 1) {
                        bean.path = it[0]
                        bean.host = it[1]
                    }
                }
            }
        }
    }

    return bean

}

private fun parseCsvVMess(csv: String): VMessBean {

    val args = csv.split(",")

    val bean = VMessBean()

    bean.serverAddress = args[1]
    bean.serverPort = args[2].toInt()
    bean.encryption = args[3]
    bean.uuid = args[4].replace("\"", "")

    args.subList(5, args.size).forEach {

        when {
            it == "over-tls=true" -> bean.security = "tls"
            it.startsWith("tls-host=") -> bean.host = it.substringAfter("=")
            it.startsWith("obfs=") -> bean.type = it.substringAfter("=")
            it.startsWith("obfs-path=") || it.contains("Host:") -> {
                runCatching {
                    bean.path = it.substringAfter("obfs-path=\"").substringBefore("\"obfs")
                }
                runCatching {
                    bean.host = it.substringAfter("Host:").substringBefore("[")
                }

            }

        }

    }

    return bean

}

fun StandardV2RayBean.toUri(): String? {
    val builder = Libcore.newURL(
        if (this is VMessBean) "vmess" else if (this is VLESSBean) "vless" else "trojan"
    )
    builder.host = serverAddress
    builder.port = serverPort
    if (this is TrojanBean) {
        builder.username = password
    } else {
        builder.username = this.uuidOrGenerate()
    }

    builder.addQueryParameter("type", when (type) {
        "splithttp" -> "xhttp"
        "tcp", "kcp", "ws", "http", "httpupgrade", "quic", "grpc", "meek", "meyka" -> type
        else -> return null
    })

    if (this !is TrojanBean) {
        builder.addQueryParameter("encryption", encryption)
    }

    when (type) {
        "tcp" -> {
            if (headerType == "http") {
                // invented by v2rayNG
                builder.addQueryParameter("headerType", headerType)
                if (host.isNotEmpty()) {
                    builder.addQueryParameter("host", host.listByLineOrComma().joinToString(","))
                }
            }
        }
        "kcp" -> {
            if (headerType.isNotEmpty() && headerType != "none") {
                builder.addQueryParameter("headerType", headerType)
            }
            if (mKcpSeed.isNotEmpty()) {
                builder.addQueryParameter("seed", mKcpSeed)
            }
        }
        "ws" -> {
            if (host.isNotEmpty()) {
                builder.addQueryParameter("host", host)
            }
            if (path.isNotEmpty()) {
                builder.addQueryParameter("path", path)
            }
            if (earlyDataHeaderName.isNotEmpty()) {
                // non-standard, invented by SagerNet and adopted by some other software
                builder.addQueryParameter("eh", earlyDataHeaderName)
            }
            if (maxEarlyData > 0) {
                // non-standard, invented by SagerNet and adopted by some other software
                builder.addQueryParameter("ed", maxEarlyData.toString())
            }
        }
        "http" -> {
            if (host.isNotEmpty()) {
                builder.addQueryParameter("host", host.listByLineOrComma().joinToString(","))
            }
            if (path.isNotEmpty()) {
                builder.addQueryParameter("path", path)
            }
        }
        "httpupgrade" -> {
            if (host.isNotEmpty()) {
                builder.addQueryParameter("host", host)
            }
            if (path.isNotEmpty()) {
                builder.addQueryParameter("path", path)
            }
            if (earlyDataHeaderName.isNotEmpty()) {
                // non-standard, invented by SagerNet and adopted by some other software
                builder.addQueryParameter("eh", earlyDataHeaderName)
            }
            if (maxEarlyData > 0) {
                // non-standard, invented by SagerNet and adopted by some other software
                builder.addQueryParameter("ed", maxEarlyData.toString())
            }
        }
        "splithttp" -> {
            if (host.isNotEmpty()) {
                builder.addQueryParameter("host", host)
            }
            if (path.isNotEmpty()) {
                builder.addQueryParameter("path", path)
            }
            if (splithttpMode != "auto") {
                builder.addQueryParameter("mode", splithttpMode)
            }
            if (splithttpExtra.isNotEmpty()) {
                JSONObject(splithttpExtra).takeIf { !it.isEmpty() }?.also {
                    // fuck RPRX `extra`
                    builder.addQueryParameter("extra", it.toString())
                }
            }
        }
        "quic" -> {
            if (headerType.isNotEmpty() && headerType != "none") {
                builder.addQueryParameter("headerType", headerType)
            }
            if (quicSecurity.isNotEmpty() && quicSecurity != "none") {
                builder.addQueryParameter("quicSecurity", quicSecurity)
                builder.addQueryParameter("key", quicKey)
            }
        }
        "grpc" -> {
            if (grpcServiceName.isNotEmpty()) {
                builder.addQueryParameter("serviceName", grpcServiceName)
            }
        }
        "meek" -> {
            // https://github.com/v2fly/v2ray-core/discussions/2638
            if (meekUrl.isNotEmpty()) {
                builder.addQueryParameter("url", meekUrl)
            }
        }
        "mekya" -> {
            // not a standard
            if (headerType != "none") {
                builder.addQueryParameter("headerType", mekyaKcpHeaderType)
            }
            if (mekyaKcpSeed.isNotEmpty()) {
                builder.addQueryParameter("seed", mekyaKcpSeed)
            }
            if (mekyaUrl.isNotEmpty()) {
                builder.addQueryParameter("url", mekyaUrl)
            }
        }
    }

    when (security) {
        "tls" -> {
            builder.addQueryParameter("security", security)
            if (sni.isNotEmpty()) {
                builder.addQueryParameter("sni", sni)
            }
            if (alpn.isNotEmpty()) {
                builder.addQueryParameter("alpn", alpn.listByLineOrComma().joinToString(","))
            }
            if (allowInsecure) {
                // bad format from where?
                builder.addQueryParameter("allowInsecure", "1")
            }
            if (this is VLESSBean && flow.isNotEmpty()) {
                builder.addQueryParameter("flow", flow.removeSuffix("-udp443"))
            }
        }
        "reality" -> {
            builder.addQueryParameter("security", security)
            if (sni.isNotEmpty()) {
                builder.addQueryParameter("sni", sni)
            }
            if (realityPublicKey.isNotEmpty()) {
                builder.addQueryParameter("pbk", realityPublicKey)
            }
            if (realityShortId.isNotEmpty()) {
                builder.addQueryParameter("sid", realityShortId)
            }
            if (realityFingerprint.isNotEmpty()) {
                builder.addQueryParameter("fp", realityFingerprint)
            }
            if (this is VLESSBean && flow.isNotEmpty()) {
                builder.addQueryParameter("flow", flow.removeSuffix("-udp443"))
            }
        }
        "none" -> builder.addQueryParameter("security", security)
    }

    if (name.isNotEmpty()) {
        builder.fragment = name
    }

    return builder.string

}