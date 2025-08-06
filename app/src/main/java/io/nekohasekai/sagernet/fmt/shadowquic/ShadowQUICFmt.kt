/******************************************************************************
 *                                                                            *
 * Copyright (C) 2025 by dyhkwong                                             *
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

package io.nekohasekai.sagernet.fmt.shadowquic

import io.nekohasekai.sagernet.LogLevel
import io.nekohasekai.sagernet.database.DataStore
import io.nekohasekai.sagernet.fmt.LOCALHOST
import io.nekohasekai.sagernet.ktx.joinHostPort
import io.nekohasekai.sagernet.ktx.listByLineOrComma
import org.yaml.snakeyaml.DumperOptions
import org.yaml.snakeyaml.Yaml

fun ShadowQUICBean.buildshadowQUICConfig(port: Int): String {
    val confObject: MutableMap<String, Any> = HashMap()

    val inboundObject: MutableMap<String, Any> = HashMap()
    inboundObject["type"] = "socks"
    inboundObject["bind-addr"] = joinHostPort(LOCALHOST, port)
    confObject["inbound"] = inboundObject

    val outboundObject: MutableMap<String, Any> = HashMap()
    outboundObject["type"] = "shadowquic"
    outboundObject["addr"] = joinHostPort(finalAddress, finalPort)
    if (password.isNotEmpty()) outboundObject["password"] = password
    if (username.isNotEmpty()) outboundObject["username"] = username
    if (sni.isNotEmpty()) outboundObject["server-name"] = sni
    if (alpn.isNotEmpty()) outboundObject["alpn"] = alpn.listByLineOrComma()
    if (congestionControl.isNotEmpty()) outboundObject["congestion-control"] = congestionControl
    if (zeroRTT) outboundObject["zero-rtt"] = zeroRTT
    if (udpOverStream) outboundObject["over-stream"] = udpOverStream
    confObject["outbound"] = outboundObject

    confObject["log-level"] = when (DataStore.logLevel) {
        LogLevel.DEBUG -> "trace"
        LogLevel.INFO -> "info"
        LogLevel.WARNING -> "warn"
        LogLevel.ERROR -> "error"
        else -> "error"
    }

    val options = DumperOptions()
    options.setDefaultFlowStyle(DumperOptions.FlowStyle.BLOCK)
    options.isPrettyFlow = true
    val yaml = Yaml(options)
    return yaml.dump(confObject)
}
