package io.nekohasekai.sagernet.fmt.anytls

import io.nekohasekai.sagernet.ktx.*
import libcore.Libcore

fun parseAnyTLS(url: String): AnyTLSBean {
    val link = Libcore.parseURL(url)
    return AnyTLSBean().apply {
        name = link.fragment
        serverAddress = link.host
        serverPort = link.port.takeIf { it > 0 } ?: 443
        password = link.username
        security = "tls"
        link.queryParameter("sni")?.also {
            sni = it
        }
        link.queryParameter("insecure")?.takeIf { it == "1" }?.also {
            allowInsecure = true
        }
    }
}

fun AnyTLSBean.toUri(): String? {
    if (security != "tls") {
        error("anytls must use tls")
    }
    val builder = Libcore.newURL("anytls")
    builder.host = serverAddress
    builder.port = serverPort
    if (password.isNotEmpty()) {
        builder.username = password
    }
    builder.rawPath = "/"
    if (sni.isNotEmpty()) {
        builder.addQueryParameter("sni", sni)
    }
    if (allowInsecure) {
        builder.addQueryParameter("insecure", "1")
    }
    if (name.isNotEmpty()) {
        builder.fragment = name
    }
    return builder.string
}
