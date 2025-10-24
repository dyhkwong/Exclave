/******************************************************************************
 *                                                                            *
 * Copyright (C) 2025  dyhkwong                                               *
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
 * along with this program. If not, see <https://www.gnu.org/licenses/>.      *
 *                                                                            *
 ******************************************************************************/

package io.nekohasekai.sagernet.group

import io.nekohasekai.sagernet.ktx.optBooleanOrNull
import io.nekohasekai.sagernet.ktx.optIntOrNull
import io.nekohasekai.sagernet.ktx.optLongOrNull
import io.nekohasekai.sagernet.ktx.optStringOrNull
import org.json.JSONArray
import org.json.JSONObject
import kotlin.collections.iterator

fun JSONObject.hasCaseInsensitive(key: String): Boolean {
    if (has(key)) {
        return true
    }
    for (it in keys()) {
        if (it.lowercase() == key.lowercase()) {
            return true
        }
    }
    return false
}

fun Map<String, Any?>.contains(key: String): Boolean {
    if (this.containsKey(key)) {
        return true
    }
    for (it in this) {
        if (it.key.lowercase() == key.lowercase()) {
            return true
        }
    }
    return false
}

fun Map<String, Any?>.getAny(key: String): Any? {
    this[key]?.also {
        return it
    }
    for (it in this) {
        if (it.key.lowercase() == key.lowercase()) {
            return it.value
        }
    }
    return null
}

fun JSONObject.optStr(key: String): String? {
    if (has(key)) {
        return optStringOrNull(key)
    }
    for (it in keys()) {
        if (it.lowercase() == key.lowercase()) {
            return optStringOrNull(it)
        }
    }
    return null
}

fun Map<String, Any?>.getString(key: String): String? {
    if (this.contains(key)) {
        return this[key] as? String
    }
    for (it in this) {
        if (it.key.lowercase() == key.lowercase()) {
            return it.value as? String
        }
    }
    return null
}

fun JSONObject.optInteger(key: String): Int? {
    if (has(key)) {
        return optIntOrNull(key)
    }
    for (it in keys()) {
        if (it.lowercase() == key.lowercase()) {
            return optIntOrNull(it)
        }
    }
    return null
}

fun Map<String, Any?>.getInteger(key: String): Int? {
    if (this.contains(key)) {
        return this[key] as? Int
    }
    for (it in this) {
        if (it.key.lowercase() == key.lowercase()) {
            return it.value as? Int
        }
    }
    return null
}

fun JSONObject.optLongInteger(key: String): Long? {
    if (has(key)) {
        return optLongOrNull(key)
    }
    for (it in keys()) {
        if (it.lowercase() == key.lowercase()) {
            return optLongOrNull(it)
        }
    }
    return null
}

fun JSONObject.optBool(key: String): Boolean? {
    if (has(key)) {
        return optBooleanOrNull(key)
    }
    for (it in keys()) {
        if (it.lowercase() == key.lowercase()) {
            return optBooleanOrNull(it)
        }
    }
    return null
}

fun Map<String, Any?>.getBoolean(key: String): Boolean? {
    if (this.contains(key)) {
        return this[key] as? Boolean
    }
    for (it in this) {
        if (it.key.lowercase() == key.lowercase()) {
            return it.value as? Boolean
        }
    }
    return null
}

fun JSONObject.optObject(key: String): JSONObject? {
    if (has(key)) {
        return optJSONObject(key)
    }
    for (it in keys()) {
        if (it.lowercase() == key.lowercase()) {
            return optJSONObject(it)
        }
    }
    return null
}

@Suppress("UNCHECKED_CAST")
fun Map<String, Any?>.getObject(key: String): Map<String, Any?>? {
    (this[key] as? Map<String, Any?>)?.also {
        return it
    }
    for (it in this) {
        if (it.key.lowercase() == key.lowercase()) {
            return it.value as? Map<String, Any?>
        }
    }
    return null
}

fun JSONObject.optArray(key: String): JSONArray? {
    if (has(key)) {
        return optJSONArray(key)
    }
    for (it in keys()) {
        if (it.lowercase() == key.lowercase()) {
            return optJSONArray(it)
        }
    }
    return null
}

@Suppress("UNCHECKED_CAST")
fun Map<String, Any?>.getArray(key: String): List<Map<String, Any?>>? {
    (this[key] as? List<Map<String, Any?>>)?.also {
        return it
    }
    for (it in this) {
        if (it.key.lowercase() == key.lowercase()) {
            return it.value as? List<Map<String, Any?>>
        }
    }
    return null
}