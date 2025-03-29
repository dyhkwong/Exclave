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
import libcore.Libcore
import java.util.*

fun parseShadowsocksR(url: String): ShadowsocksRBean {

    val params = url.substringAfter("ssr://").decodeBase64UrlSafe().split(":")

    val bean = ShadowsocksRBean().apply {
        serverAddress = params[0]
        serverPort = params[1].toInt()
        protocol = params[2]
        method = params[3]
        obfs = when (val it = params[4]) {
            "tls1.2_ticket_fastauth" -> "tls1.2_ticket_auth"
            else -> it
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
            serverAddress,
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
