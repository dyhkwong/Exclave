/******************************************************************************
 *                                                                            *
 * Copyright (C) 2023  dyhkwong                                               *
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

package io.nekohasekai.sagernet.fmt.hysteria2

import io.nekohasekai.sagernet.Key
import io.nekohasekai.sagernet.TunImplementation
import io.nekohasekai.sagernet.database.DataStore
import io.nekohasekai.sagernet.fmt.LOCALHOST
import io.nekohasekai.sagernet.ktx.isValidHysteriaMultiPort
import io.nekohasekai.sagernet.ktx.isValidHysteriaPort
import io.nekohasekai.sagernet.ktx.joinHostPort
import io.nekohasekai.sagernet.ktx.listByLineOrComma
import io.nekohasekai.sagernet.ktx.queryParameter
import libcore.Libcore
import org.yaml.snakeyaml.DumperOptions
import org.yaml.snakeyaml.Yaml
import java.io.File

fun parseHysteria2(rawURL: String): Hysteria2Bean {
    var url = rawURL

    // fuck port hopping URL
    val hostPort = url.substringAfter("://").substringAfter("@")
        .substringBefore("#").substringBefore("?").substringBefore("/")
    var port = ""
    if (!hostPort.endsWith("]") && hostPort.lastIndexOf(":") > 0) {
        port = hostPort.substringAfterLast(":")
    }
    if (port.isNotEmpty() && port.isValidHysteriaMultiPort()) {
        url = url.replace(":$port", ":0")
    }

    val link = Libcore.parseURL(url)
    return Hysteria2Bean().apply {
        name = link.fragment
        serverAddress = link.host
        serverPorts = if (port.isNotEmpty() && port.isValidHysteriaMultiPort()) {
            port
        } else if (link.port > 0) {
            link.port.toString()
        } else {
            "443"
        }
        link.queryParameter("mport")?.takeIf { it.isValidHysteriaMultiPort() }?.also {
            serverPorts = it
        }
        when {
            // Warning: Do not use colon in username or password in so-called `userpass` authentication.
            // Official Hysteria2 server can not handle it correctly.
            // need to handle so-called broken "userpass" authentication
            link.username.isEmpty() && link.password.isEmpty() -> {
                if (rawURL.substringAfter("://").substringBefore("@") == ":") {
                    auth = ":"
                }
            }
            link.username.isNotEmpty() && link.password.isEmpty() -> {
                auth = if (rawURL.substringAfter("://").substringBefore("@").endsWith(":")) {
                    link.username + ":"
                } else {
                    link.username
                }
            }
            link.username.isEmpty() && link.password.isNotEmpty() -> {
                auth = ":" + link.password
            }
            link.username.isNotEmpty() && link.password.isNotEmpty() -> {
                auth = link.username + ":" + link.password
            }
        }
        link.queryParameter("sni")?.also {
            sni = it
        }
        link.queryParameter("insecure")?.takeIf { it == "1" || it == "true" }?.also {
            allowInsecure = true
        }
        link.queryParameter("pinSHA256")?.also {
            // https://github.com/apernet/hysteria/blob/922128e425a700c5bc01290e7a9560f182fe451b/app/cmd/client.go#L882-L889
            pinnedPeerCertificateSha256 = it.replace(":", "").replace("-", "").lowercase()
        }
        link.queryParameter("obfs")?.also {
            if (it.isNotEmpty() && it != "salamander") {
                error("unsupported obfs")
            }
            link.queryParameter("obfs-password")?.also {
                obfs = it
            }
        }
    }
}

fun Hysteria2Bean.toUri(): String? {
    if (!serverPorts.isValidHysteriaPort()) {
        error("invalid port")
    }

    val builder = Libcore.newURL("hysteria2").apply {
        host = serverAddress.ifEmpty { error("empty server address") }
        port = if (serverPorts.isValidHysteriaMultiPort()) {
            0 // placeholder
        } else {
            serverPorts.toInt()
        }
        if (auth.isNotEmpty()) {
            // No need to care about so-called broken "userpass" here.
            username = auth
        }
    }

    if (sni.isNotEmpty()) {
        builder.addQueryParameter("sni", sni)
    }
    // as `pinnedPeerCertificate[Chain|PublicKey]Sha256` is not exportable,
    // only add `allow_insecure=1` if `pinnedPeerCertificate[Chain|PublicKey]Sha256` is not used
    if (allowInsecure &&
        pinnedPeerCertificateChainSha256.isEmpty() && pinnedPeerCertificatePublicKeySha256.isEmpty()) {
        builder.addQueryParameter("insecure", "1")
    }
    if (pinnedPeerCertificateSha256.isNotEmpty()) {
        builder.addQueryParameter("pinSHA256", pinnedPeerCertificateSha256.listByLineOrComma()[0].replace(":", "").lowercase())
    }
    if (obfs.isNotEmpty()) {
        // obfs password must not be empty
        builder.addQueryParameter("obfs", "salamander")
        builder.addQueryParameter("obfs-password", obfs)
    }
    if (name.isNotEmpty()) {
        builder.fragment = name
    }
    builder.rawPath = "/"

    val url = builder.string
    if (serverPorts.isValidHysteriaMultiPort()) {
        // fuck port hopping URL
        val port = url.substringAfter("://").substringAfter("@")
            .substringBefore("/").substringAfterLast(":")
        return url.replace(":$port/", ":$serverPorts/")
    }
    return url
}

fun Hysteria2Bean.buildHysteria2Config(port: Int, isVpn: Boolean = false, cacheFile: ((type: String) -> File)? = null): String {
    if (!serverPorts.isValidHysteriaPort()) {
        error("invalid port: $serverPorts")
    }
    val usePortHopping = DataStore.hysteriaEnablePortHopping && serverPorts.isValidHysteriaMultiPort()

    val hostPort = if (usePortHopping) {
        // Hysteria 2 port hopping is incompatible with chain proxy
        if (Libcore.isIPv6(serverAddress)) {
            "[$serverAddress]:$serverPorts"
        } else {
            "$serverAddress:$serverPorts"
        }
    } else {
        joinHostPort(finalAddress, finalPort)
    }

    val confObject: MutableMap<String, Any> = HashMap()
    confObject["server"] = hostPort
    if (auth.isNotEmpty()) {
        confObject["auth"] = auth
    }

    val tlsObject: MutableMap<String, Any> = HashMap()
    if (allowInsecure) {
        tlsObject["insecure"] = true
    }
    var servername = sni
    if (!usePortHopping) {
        if (servername.isEmpty()) {
            servername = serverAddress
        }
    }
    if (servername.isNotEmpty()) {
        tlsObject["sni"] = servername
    }
    if (certificates.isNotEmpty() && cacheFile != null) {
        val file = cacheFile("ca")
        file.writeText(certificates)
        tlsObject["ca"] = file.absolutePath
    }
    if (mtlsCertificate.isNotEmpty() && cacheFile != null) {
        val file = cacheFile("clientCertificate")
        file.writeText(mtlsCertificate)
        tlsObject["clientCertificate"] = file.absolutePath
    }
    if (mtlsCertificatePrivateKey.isNotEmpty() && cacheFile != null) {
        val file = cacheFile("clientKey")
        file.writeText(mtlsCertificatePrivateKey)
        tlsObject["clientKey"] = file.absolutePath
    }
    if (pinnedPeerCertificateSha256.isNotEmpty()) {
        tlsObject["pinSHA256"] = pinnedPeerCertificateSha256.listByLineOrComma()[0].replace(":", "")
    }
    if (tlsObject.isNotEmpty()) {
        confObject["tls"] = tlsObject
    }

    val transportObject: MutableMap<String, Any> = HashMap()
    transportObject["type"] = "udp"
    if (DataStore.hysteriaEnablePortHopping && serverPorts.isValidHysteriaMultiPort() && hopInterval > 0) {
        val udpObject: MutableMap<String, Any> = HashMap()
        udpObject["hopInterval"] = "$hopInterval" + "s"
        transportObject["udp"] = udpObject
    }
    confObject["transport"] = transportObject

    if (obfs.isNotEmpty()) {
        val obfsObject: MutableMap<String, Any> = HashMap()
        obfsObject["type"] = "salamander"
        val salamanderObject: MutableMap<String, Any> = HashMap()
        salamanderObject["password"] = obfs
        obfsObject["salamander"] = salamanderObject
        confObject["obfs"] = obfsObject
    }

    val quicObject: MutableMap<String, Any> = HashMap()
    if (disableMtuDiscovery) {
        quicObject["disableMtuDiscovery"] = true
    }
    if (initStreamReceiveWindow > 0) {
        quicObject["initStreamReceiveWindow"] = initStreamReceiveWindow
    }
    if (maxStreamReceiveWindow > 0) {
        quicObject["maxStreamReceiveWindow"] = maxStreamReceiveWindow
    }
    if (initConnReceiveWindow > 0) {
        quicObject["initConnReceiveWindow"] = initConnReceiveWindow
    }
    if (maxConnReceiveWindow > 0) {
        quicObject["maxConnReceiveWindow"] = maxConnReceiveWindow
    }
    if (needProtect() && DataStore.tunImplementation == TunImplementation.SYSTEM && DataStore.serviceMode == Key.MODE_VPN && isVpn) {
        val sockoptsObject: MutableMap<String, Any> = HashMap()
        sockoptsObject["fdControlUnixSocket"] = "protect_path"
        quicObject["sockopts"] = sockoptsObject
    }
    if (quicObject.isNotEmpty()) {
        confObject["quic"] = quicObject
    }

    val bandwidthObject: MutableMap<String, Any> = HashMap()
    if (uploadMbps > 0) {
        bandwidthObject["up"] = "$uploadMbps mbps"
    }
    if (downloadMbps > 0) {
        bandwidthObject["down"] = "$downloadMbps mbps"
    }
    if (bandwidthObject.isNotEmpty()) {
        confObject["bandwidth"] = bandwidthObject
    }

    val socks5Object: MutableMap<String, Any> = HashMap()
    socks5Object["listen"] = joinHostPort(LOCALHOST, port)
    confObject["socks5"] = socks5Object

    confObject["lazy"] = true
    confObject["fastOpen"] = true

    val options = DumperOptions()
    options.setDefaultFlowStyle(DumperOptions.FlowStyle.BLOCK)
    options.isPrettyFlow = true
    val yaml = Yaml(options)
    return yaml.dump(confObject)
}
