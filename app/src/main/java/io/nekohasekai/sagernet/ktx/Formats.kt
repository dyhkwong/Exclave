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

package io.nekohasekai.sagernet.ktx

import cn.hutool.core.codec.Base64
import io.nekohasekai.sagernet.fmt.AbstractBean
import io.nekohasekai.sagernet.fmt.Serializable
import io.nekohasekai.sagernet.fmt.anytls.parseAnyTLS
import io.nekohasekai.sagernet.fmt.brook.parseBrook
import io.nekohasekai.sagernet.fmt.http.parseHttp
import io.nekohasekai.sagernet.fmt.http3.parseHttp3
import io.nekohasekai.sagernet.fmt.hysteria.parseHysteria
import io.nekohasekai.sagernet.fmt.hysteria2.parseHysteria2
import io.nekohasekai.sagernet.fmt.juicity.parseJuicity
import io.nekohasekai.sagernet.fmt.mieru.parseMieru
import io.nekohasekai.sagernet.fmt.naive.parseNaive
import io.nekohasekai.sagernet.fmt.parseBackupLink
import io.nekohasekai.sagernet.fmt.shadowsocks.parseShadowsocks
import io.nekohasekai.sagernet.fmt.shadowsocksr.parseShadowsocksR
import io.nekohasekai.sagernet.fmt.socks.parseSOCKS
import io.nekohasekai.sagernet.fmt.trojan_go.parseTrojanGo
import io.nekohasekai.sagernet.fmt.tuic5.parseTuic
import io.nekohasekai.sagernet.fmt.v2ray.parseV2Ray
import io.nekohasekai.sagernet.fmt.wireguard.parseV2rayNWireGuard

fun String.decodeBase64UrlSafe(): String {
    return Base64.decodeStr(
        replace(' ', '-').replace('/', '_').replace('+', '-').replace("=", "")
    )
}

class SubscriptionFoundException(val link: String) : RuntimeException()

fun parseShareLinks(text: String): List<AbstractBean> {
    val links = text.split('\n').flatMap { it.trim().split(' ') }
    val linksByLine = text.split('\n').map { it.trim() }

    val entities = ArrayList<AbstractBean>()
    val entitiesByLine = ArrayList<AbstractBean>()

    fun String.parseLink(entities: ArrayList<AbstractBean>) {
        if (startsWith("exclave://subscription") || startsWith("sn://subscription")) {
            throw SubscriptionFoundException(this)
        }

        if (startsWith("exclave://")) {
            runCatching {
                entities.add(parseBackupLink(this))
            }
        } else if (startsWith("socks://") || startsWith("socks4://") || startsWith("socks4a://") ||
            startsWith("socks5://") || startsWith("socks5h://")) {
            runCatching {
                entities.add(parseSOCKS(this))
            }
        } else if (matches("(http|https)://.*".toRegex())) {
            runCatching {
                entities.add(parseHttp(this))
            }
        } else if (startsWith("vmess://") || startsWith("vless://") || startsWith("trojan://")) {
            runCatching {
                entities.add(parseV2Ray(this))
            }
        } else if (startsWith("trojan-go://")) {
            runCatching {
                entities.add(parseTrojanGo(this))
            }
        } else if (startsWith("ss://")) {
            runCatching {
                entities.add(parseShadowsocks(this))
            }
        } else if (startsWith("ssr://")) {
            runCatching {
                entities.add(parseShadowsocksR(this))
            }
        } else if (startsWith("naive+https") || startsWith("naive+quic")) {
            runCatching {
                entities.add(parseNaive(this))
            }
        } else if (startsWith("brook://")) {
            runCatching {
                entities.add(parseBrook(this))
            }
        } else if (startsWith("hysteria://")) {
            runCatching {
                entities.add(parseHysteria(this))
            }
        } else if (startsWith("hysteria2://") || startsWith("hy2://")) {
            runCatching {
                entities.add(parseHysteria2(this))
            }
        } else if (startsWith("juicity://")) {
            runCatching {
                entities.add(parseJuicity(this))
            }
        } else if (startsWith("tuic://")) {
            runCatching {
                entities.add(parseTuic(this))
            }
        } else if (startsWith("wireguard://")) {
            runCatching {
                entities.add(parseV2rayNWireGuard(this))
            }
        } else if (startsWith("mierus://")) {
            runCatching {
                entities.add(parseMieru(this))
            }
        } else if (startsWith("quic://")) {
            runCatching {
                entities.add(parseHttp3(this))
            }
        } else if (startsWith("anytls://")) {
            runCatching {
                entities.add(parseAnyTLS(this))
            }
        }
    }

    for (link in links) {
        link.parseLink(entities)
    }
    for (link in linksByLine) {
        link.parseLink(entitiesByLine)
    }

    return if (entities.size > entitiesByLine.size) entities else entitiesByLine
}

fun <T : Serializable> T.applyDefaultValues(): T {
    initializeDefaultValues()
    return this
}