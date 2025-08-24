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