package io.nekohasekai.sagernet.fmt.juicity

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
            pinnedCertChainSha256 = it
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
    if (allowInsecure) {
        builder.addQueryParameter("allow_insecure", "1")
    }
    if (sni.isNotEmpty()) {
        builder.addQueryParameter("sni", sni)
    }
    if (pinnedCertChainSha256.isNotEmpty()) {
        builder.addQueryParameter("pinned_certchain_sha256", pinnedCertChainSha256)
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
        if (allowInsecure) {
            it["allow_insecure"] = allowInsecure
        }
        if (pinnedCertChainSha256.isNotEmpty()) {
            it["pinned_certchain_sha256"] = pinnedCertChainSha256
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
