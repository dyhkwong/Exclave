package io.nekohasekai.sagernet.fmt.ssh

import libcore.Libcore

fun parseSSH(link: String): SSHBean {
    // Warning: no public key pinning is insecure!
    val url = Libcore.parseURL(link)
    return SSHBean().apply {
        serverAddress = url.host
        serverPort = url.port.takeIf { it > 0 } ?: 22
        username = url.username
        password = url.password
        name = url.fragment
        if (url.password.isNotEmpty()) {
            authType = SSHBean.AUTH_TYPE_PASSWORD
        }
    }
}
