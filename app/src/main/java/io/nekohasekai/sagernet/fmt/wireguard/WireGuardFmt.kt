package io.nekohasekai.sagernet.fmt.wireguard

import io.nekohasekai.sagernet.ktx.applyDefaultValues
import io.nekohasekai.sagernet.ktx.joinHostPort
import io.nekohasekai.sagernet.ktx.listByLineOrComma
import io.nekohasekai.sagernet.ktx.queryParameter
import libcore.Libcore
import org.ini4j.Ini
import java.io.StringReader
import java.io.StringWriter

fun parseWireGuard(server: String): WireGuardBean {
    val link = Libcore.parseURL(server)
    return WireGuardBean().apply {
        serverAddress = link.host
        serverPort = link.port.takeIf { it > 0 } ?: 51820
        if (link.username.isNotEmpty()) {
            // https://github.com/XTLS/Xray-core/blob/d8934cf83946e88210b6bb95d793bc06e12b6db8/infra/conf/wireguard.go#L126-L148
            privateKey = link.username.replace('_', '/').replace('-', '+').padEnd(44, '=')
            // v2rayNG style link
            // https://github.com/XTLS/Xray-core/blob/d8934cf83946e88210b6bb95d793bc06e12b6db8/infra/conf/wireguard.go#L75
            localAddress = "10.0.0.1/32\nfd59:7153:2388:b5fd:0000:0000:0000:0001/128"
        }
        (link.queryParameter("privatekey") ?: link.queryParameter("privateKey")) ?.let {
            privateKey = it.replace('_', '/').replace('-', '+').padEnd(44, '=')
        }
        (link.queryParameter("address") ?: link.queryParameter("ip")) ?.takeIf { it.isNotEmpty() }?.also {
            localAddress = it.split(",").joinToString("\n")
        }
        (link.queryParameter("publickey") ?: link.queryParameter("publicKey")) ?.let {
            peerPublicKey = it.replace('_', '/').replace('-', '+').padEnd(44, '=')
        }
        (link.queryParameter("presharedkey") ?: link.queryParameter("preSharedKey")) ?.let {
            peerPreSharedKey = it.replace('_', '/').replace('-', '+').padEnd(44, '=')
        }
        link.queryParameter("mtu")?.toIntOrNull()?.takeIf { it > 0 }?.let {
            mtu = it
        }
        link.queryParameter("reserved")?.let {
            reserved = it
        }
        link.fragment?.let {
            name = it
        }
    }
}

fun parseWireGuardConfig(conf: String): List<WireGuardBean> {
    val beans = mutableListOf<WireGuardBean>()
    val ini = Ini(StringReader(conf)).apply {
        config.isMultiSection = true
    }
    if (ini.size == 0) {
        return beans
    }
    val iface = ini["Interface"] ?: return beans
    val localAddresses = iface.getAll("Address")
    if (localAddresses.isNullOrEmpty()) {
        return beans
    }
    val peers = ini.getAll("Peer")
    if (peers.isNullOrEmpty()) {
        return beans
    }
    val wgBean = WireGuardBean().apply {
        localAddress = localAddresses.flatMap {
            it.filterNot { it.isWhitespace() }.split(",")
        }.joinToString("\n")
        privateKey = iface["PrivateKey"]
        mtu = iface["MTU"]?.toInt()?.takeIf { it > 0 } ?: 1420
    }
    for (peer in peers) {
        val endpoint = peer["Endpoint"]
        if (endpoint.isNullOrEmpty() || !endpoint.contains(":")) {
            continue
        }
        val port = endpoint.substringAfterLast(":").toIntOrNull() ?: continue
        val publicKey = peer["PublicKey"] ?: continue
        beans.add(wgBean.applyDefaultValues().clone().apply {
            serverAddress = endpoint.substringBeforeLast(":").removePrefix("[").removeSuffix("]")
            serverPort = port
            peerPreSharedKey = peer["PreSharedKey"]
            keepaliveInterval = peer["PersistentKeepalive"]?.toIntOrNull()?.takeIf { it > 0 }
            peerPublicKey = publicKey
        })
    }
    return beans
}

fun WireGuardBean.toConf(): String {
    val ini = Ini().apply {
        config.isEscape = false
    }
    ini.add("Interface", "Address", localAddress.listByLineOrComma().joinToString(", "))
    if (mtu > 0) {
        ini.add("Interface", "MTU", mtu)
    }
    ini.add(
        "Interface",
        "PrivateKey",
        privateKey.ifEmpty { error("empty private key") }
    )
    ini.add(
        "Peer",
        "Endpoint",
        joinHostPort(serverAddress.ifEmpty { error("empty server address") }, serverPort)
    )
    ini.add(
        "Peer",
        "PublicKey",
        peerPublicKey.ifEmpty { error("empty peer public key") }
    )
    if (peerPreSharedKey.isNotEmpty()) {
        ini.add("Peer", "PreSharedKey", peerPreSharedKey)
    }
    if (keepaliveInterval > 0) {
        ini.add("Peer", "PersistentKeepalive", keepaliveInterval)
    }
    val conf = StringWriter()
    ini.store(conf)
    return conf.toString()
}
