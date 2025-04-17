package io.nekohasekai.sagernet.fmt.wireguard

import io.nekohasekai.sagernet.fmt.AbstractBean
import io.nekohasekai.sagernet.ktx.applyDefaultValues
import io.nekohasekai.sagernet.ktx.joinHostPort
import io.nekohasekai.sagernet.ktx.listByLineOrComma
import io.nekohasekai.sagernet.ktx.queryParameter
import libcore.Libcore
import org.ini4j.Ini
import java.io.StringReader
import java.io.StringWriter

fun parseV2rayNWireGuard(server: String): AbstractBean {
    val link = Libcore.parseURL(server)
    return WireGuardBean().apply {
        serverAddress = link.host
        serverPort = link.port
        if (link.username.isNotEmpty()) {
            // https://github.com/XTLS/Xray-core/blob/d8934cf83946e88210b6bb95d793bc06e12b6db8/infra/conf/wireguard.go#L126-L148
            privateKey = link.username.replace('_', '/').replace('-', '+').padEnd(44, '=')
        }
        link.queryParameter("address")?.takeIf { it.isNotEmpty() }?.also {
            localAddress = it.split(",").joinToString("\n")
        }
        link.queryParameter("publickey")?.let {
            peerPublicKey = it.replace('_', '/').replace('-', '+').padEnd(44, '=')
        }
        link.queryParameter("presharedkey")?.let {
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
    ini.add("Interface", "PrivateKey", privateKey)
    ini.add("Peer", "Endpoint", joinHostPort(serverAddress, serverPort))
    ini.add("Peer", "PublicKey", peerPublicKey)
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
