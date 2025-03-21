package io.nekohasekai.sagernet.fmt.wireguard

import io.nekohasekai.sagernet.fmt.AbstractBean
import io.nekohasekai.sagernet.ktx.joinHostPort
import io.nekohasekai.sagernet.ktx.listByLineOrComma
import io.nekohasekai.sagernet.ktx.queryParameter
import libcore.Libcore
import org.ini4j.Ini
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
        link.fragment.takeIf { !it.isNullOrEmpty() }?.let {
            name = it
        }
    }
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
