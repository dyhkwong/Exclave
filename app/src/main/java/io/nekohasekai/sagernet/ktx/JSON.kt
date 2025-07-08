package io.nekohasekai.sagernet.ktx

import cn.hutool.json.JSONArray
import cn.hutool.json.JSONObject

fun JSONObject.contains(key: String): Boolean {
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

fun JSONObject.getAny(key: String): Any? {
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

fun JSONObject.getString(key: String): String? {
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

fun JSONObject.getInteger(key: String): Int? {
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

fun JSONObject.getLongInteger(key: String): Long? {
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

fun JSONObject.getBoolean(key: String): Boolean? {
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

fun JSONObject.getIntFromStringOrInt(key: String): Int? {
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

fun JSONObject.getObject(key: String): JSONObject? {
    (this[key] as? JSONObject)?.also {
        return it
    }
    for (it in this) {
        if (it.key.lowercase() == key.lowercase()) {
            return it.value as? JSONObject
        }
    }
    return null
}

fun JSONObject.getArray(key: String): JSONArray? {
    (this[key] as? JSONArray)?.also {
        return it
    }
    for (it in this) {
        if (it.key.lowercase() == key.lowercase()) {
            return it.value as? JSONArray
        }
    }
    return null
}
