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

package io.nekohasekai.sagernet.group

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

fun Map<String, Any?>.getString(key: String): String? {
    (this[key] as? String)?.also {
        return it
    }
    for (it in this) {
        if (it.key.lowercase() == key.lowercase()) {
            return it.value as? String
        }
    }
    return null
}

fun Map<String, Any?>.getInteger(key: String): Int? {
    (this[key] as? Int)?.also {
        return it
    }
    for (it in this) {
        if (it.key.lowercase() == key.lowercase()) {
            return it.value as? Int
        }
    }
    return null
}

fun Map<String, Any?>.getLongInteger(key: String): Long? {
    (this[key] as? Long)?.also {
        return it
    }
    for (it in this) {
        if (it.key.lowercase() == key.lowercase()) {
            return it.value as? Long
        }
    }
    return null
}

fun Map<String, Any?>.getBoolean(key: String): Boolean? {
    (this[key] as? Boolean)?.also {
        return it
    }
    for (it in this) {
        if (it.key.lowercase() == key.lowercase()) {
            return it.value as? Boolean
        }
    }
    return null
}

fun Map<String, Any?>.getIntFromStringOrInt(key: String): Int? {
    (this[key]?.toString()?.toInt())?.also {
        return it
    }
    for (it in this) {
        if (it.key.lowercase() == key.lowercase()) {
            return it.value?.toString()?.toInt()
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

fun String.toUIntOrNull(): Int? {
    // Clash's custom int parser
    if (this.contains(":")) return null
    if (this.contains("-")) return null
    val newStr = this.lowercase().removePrefix("+")
    if (newStr.contains("+")) return null
    if (newStr.startsWith("0x")) {
        return newStr.removePrefix("0x").replace("_", "").toIntOrNull(16)
    }
    if (newStr.startsWith("0b")) {
        return newStr.removePrefix("0b").replace("_", "").toIntOrNull(2)
    }
    if (newStr.startsWith("0o")) {
        return newStr.removePrefix("0o").replace("_", "").toIntOrNull(8)
    }
    if (newStr.startsWith("0")) {
        return newStr.removePrefix("0").replace("_", "").toIntOrNull(8)
    }
    if (newStr.startsWith("_")) {
        return null
    }
    return newStr.replace("_", "").toIntOrNull()
}