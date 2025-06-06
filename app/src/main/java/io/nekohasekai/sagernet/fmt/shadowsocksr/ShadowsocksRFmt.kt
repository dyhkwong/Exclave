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

package io.nekohasekai.sagernet.fmt.shadowsocksr

import cn.hutool.core.codec.Base64
import io.nekohasekai.sagernet.ktx.decodeBase64UrlSafe
import io.nekohasekai.sagernet.ktx.queryParameter
import io.nekohasekai.sagernet.ktx.unwrapIDN
import libcore.Libcore
import java.util.*

val supportedShadowsocksRMethod = arrayOf(
    "rc4","rc4-md5","rc4-md5-6",
    "aes-128-ctr","aes-192-ctr","aes-256-ctr",
    "aes-128-cfb","aes-192-cfb","aes-256-cfb",
    "aes-128-cfb8","aes-192-cfb8","aes-256-cfb8",
    "aes-128-ofb","aes-192-ofb","aes-256-ofb",
    "bf-cfb","cast5-cfb","des-cfb","rc2-cfb","seed-cfb",
    "camellia-128-cfb","camellia-192-cfb","camellia-256-cfb",
    "camellia-128-cfb8","camellia-192-cfb8","camellia-256-cfb8",
    "salsa20","chacha20","chacha20-ietf","xchacha20",
    "none", "table"
)

val supportedShadowsocksRProtocol = arrayOf(
    "origin", "auth_sha1_v4", "auth_aes128_sha1", "auth_aes128_md5", "auth_chain_a", "auth_chain_b"
)

val supportedShadowsocksRObfs = arrayOf(
    "plain", "http_simple", "http_post", "tls1.2_ticket_auth", "random_head"
)

fun parseShadowsocksR(url: String): ShadowsocksRBean {

    val params = url.substringAfter("ssr://").decodeBase64UrlSafe().split(":")

    val bean = ShadowsocksRBean().apply {
        serverAddress = params[0].unwrapIDN()
        serverPort = params[1].toIntOrNull() ?: error("invalid port")
        protocol = params[2].takeIf { it in supportedShadowsocksRProtocol } ?: error("unsupported protocol")
        method = params[3].takeIf { it in supportedShadowsocksRMethod } ?: error("unsupported method")
        obfs = when (val it = params[4]) {
            "tls1.2_ticket_fastauth" -> "tls1.2_ticket_auth"
            else -> it.takeIf { it in supportedShadowsocksRObfs } ?: error("unsupported obfs")
        }
        password = params[5].substringBefore("/").decodeBase64UrlSafe()
    }

    val httpUrl = Libcore.parseURL("https://localhost" + params[5].substringAfter("/"))

    httpUrl.queryParameter("obfsparam")?.let {
        bean.obfsParam = it.decodeBase64UrlSafe()
    }

    httpUrl.queryParameter("protoparam")?.let {
        bean.protocolParam = it.decodeBase64UrlSafe()
    }

    httpUrl.queryParameter("remarks")?.let {
        bean.name = it.decodeBase64UrlSafe()
    }

    return bean

}

fun ShadowsocksRBean.toUri(): String {
    return "ssr://" + Base64.encodeUrlSafe(
        "%s:%d:%s:%s:%s:%s/?obfsparam=%s&protoparam=%s&remarks=%s".format(
            Locale.ENGLISH,
            serverAddress.ifEmpty { error("empty server address") },
            serverPort,
            protocol,
            method,
            obfs,
            Base64.encodeUrlSafe("%s".format(Locale.ENGLISH, password)),
            Base64.encodeUrlSafe("%s".format(Locale.ENGLISH, obfsParam)),
            Base64.encodeUrlSafe("%s".format(Locale.ENGLISH, protocolParam)),
            Base64.encodeUrlSafe(
                "%s".format(
                    Locale.ENGLISH, name ?: ""
                )
            )
        )
    )
}
