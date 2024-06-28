package io.nekohasekai.sagernet.fmt.juicity

import cn.hutool.json.JSONObject
import io.nekohasekai.sagernet.database.DataStore
import io.nekohasekai.sagernet.fmt.LOCALHOST
import io.nekohasekai.sagernet.ktx.*
import libcore.Libcore

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
            congestionControl = it
        }
        link.queryParameter("pinned_certchain_sha256")?.also {
            pinnedCertChainSha256 = it
        }
    }
}

fun JuicityBean.toUri(): String {
    val builder = Libcore.newURL("juicity")
    builder.host = serverAddress
    builder.port = serverPort
    builder.username = uuid
    builder.password = password
    if (congestionControl.isNotBlank()) {
        builder.addQueryParameter("congestion_control", congestionControl)
    }
    if (allowInsecure) {
        builder.addQueryParameter("allow_insecure", "1")
    }
    if (sni.isNotBlank()) {
        builder.addQueryParameter("sni", sni)
    }
    if (pinnedCertChainSha256.isNotBlank()) {
        builder.addQueryParameter("pinned_certchain_sha256", pinnedCertChainSha256)
    }
    if (name.isNotBlank()) {
        builder.setRawFragment(name.urlSafe())
    }
    return builder.string
}

fun JuicityBean.buildJuicityConfig(port: Int): String {
    return JSONObject().also {
        it["listen"] = "$LOCALHOST:$port"
        it["server"] = wrapUri()
        it["uuid"] = uuid
        it["password"] = password
        it["congestion_control"] = congestionControl
        if (sni.isNotBlank()) {
            it["sni"] = sni
        } else if (!serverAddress.isIpAddress()) {
            it["sni"] = serverAddress
        }
        if (allowInsecure) {
            it["allow_insecure"] = allowInsecure
        }
        if (pinnedCertChainSha256.isNotBlank()) {
            it["pinned_certchain_sha256"] = pinnedCertChainSha256
        }
        if (DataStore.enableLog) {
            it["log_level"] = "debug"
        } else {
            it["log_level"] = "error"
        }

    }.toStringPretty()
}
