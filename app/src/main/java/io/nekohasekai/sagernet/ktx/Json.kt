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

import com.google.gson.JsonArray
import com.google.gson.JsonElement
import com.google.gson.JsonObject
import com.google.gson.JsonParser.parseReader
import com.google.gson.Strictness
import com.google.gson.stream.JsonReader
import java.io.StringReader

fun parseJson(text: String): JsonElement {
    val jsonReader = JsonReader(StringReader(text)).apply {
        strictness = Strictness.STRICT
    }
    return parseReader(jsonReader)
}

fun parseJsonLeniently(text: String): JsonElement {
    val jsonReader = JsonReader(StringReader(text)).apply {
        strictness = Strictness.LENIENT
    }
    return parseReader(jsonReader)
}

fun JsonObject.contains(key: String, ignoreCase: Boolean = false): Boolean {
    if (has(key)) {
        return true
    }
    if (ignoreCase) {
        for (it in keySet()) {
            if (it.equals(key, ignoreCase = true)) {
                return true
            }
        }
    }
    return false
}

fun JsonObject.getString(key: String, ignoreCase: Boolean = false): String? {
    if (has(key)) {
        return try {
            get(key).asString
        } catch (_: Exception) {
            null
        }
    }
    if (ignoreCase) {
        for (it in keySet()) {
            if (it.equals(key, ignoreCase = true)) {
                return try {
                    get(it).asString
                } catch (_: Exception) {
                    null
                }
            }
        }
    }
    return null
}

fun JsonObject.getInt(key: String, ignoreCase: Boolean = false): Int? {
    if (has(key)) {
        return try {
            get(key).asInt
        } catch (_: Exception) {
            null
        }
    }
    if (ignoreCase) {
        for (it in keySet()) {
            if (it.equals(key, ignoreCase = true)) {
                return try {
                    get(it).asInt
                } catch (_: Exception) {
                    null
                }
            }
        }
    }
    return null
}

fun JsonObject.getBoolean(key: String, ignoreCase: Boolean = false): Boolean? {
    if (has(key)) {
        return try {
            get(key).asBoolean
        } catch (_: Exception) {
            null
        }
    }
    if (ignoreCase) {
        for (it in keySet()) {
            if (it.equals(key, ignoreCase = true)) {
                return try {
                    get(it).asBoolean
                } catch (_: Exception) {
                    null
                }
            }
        }
    }
    return null
}

fun JsonObject.getLong(key: String, ignoreCase: Boolean = false): Long? {
    if (has(key)) {
        return try {
            get(key).asLong
        } catch (_: Exception) {
            null
        }
    }
    if (ignoreCase) {
        for (it in keySet()) {
            if (it.equals(key, ignoreCase = true)) {
                return try {
                    get(it).asLong
                } catch (_: Exception) {
                    null
                }
            }
        }
    }
    return null
}

fun JsonObject.getObject(key: String, ignoreCase: Boolean = false): JsonObject? {
    if (has(key)) {
        return try {
            get(key).asJsonObject
        } catch (_: Exception) {
            null
        }
    }
    if (ignoreCase) {
        for (it in keySet()) {
            if (it.equals(key, ignoreCase = true)) {
                return try {
                    get(it).asJsonObject
                } catch (_: Exception) {
                    null
                }
            }
        }
    }
    return null
}

private fun JsonObject.getJsonArray(key: String, ignoreCase: Boolean = false): JsonArray? {
    if (has(key)) {
        return try {
            get(key).asJsonArray
        } catch (_: Exception) {
            null
        }
    }
    if (ignoreCase) {
        for (it in keySet()) {
            if (it.equals(key, ignoreCase = true)) {
                return try {
                    get(it).asJsonArray
                } catch (_: Exception) {
                    null
                }
            }
        }
    }
    return null
}

fun JsonObject.getArray(key: String, ignoreCase: Boolean = false): List<JsonObject>? {
    val array = getJsonArray(key, ignoreCase)?.asList() ?: return null
    val list = mutableListOf<JsonObject>()
    try {
        for (obj in array) {
            list.add(obj.asJsonObject)
        }
    } catch (_: Exception) {
        return null
    }
    return list
}

fun JsonObject.getStringArray(key: String, ignoreCase: Boolean = false): List<String>? {
    val array = getJsonArray(key, ignoreCase)?.asList() ?: return null
    val list = mutableListOf<String>()
    try {
        for (obj in array) {
            list.add(obj.asString)
        }
    } catch (_: Exception) {
        return null
    }
    return list
}

fun JsonObject.getIntArray(key: String, ignoreCase: Boolean = false): List<Int>? {
    val array = getJsonArray(key, ignoreCase)?.asList() ?: return null
    val list = mutableListOf<Int>()
    try {
        for (obj in array) {
            list.add(obj.asInt)
        }
    } catch (_: Exception) {
        return null
    }
    return list
}

fun isEscaped(jsonString: String, quotePosition: Int): Boolean {
    var index = quotePosition - 1
    var backslashCount = 0
    if (index < 0) {
        return false
    }
    while (jsonString[index] == '\\') {
        index -= 1
        backslashCount += 1
    }
    return backslashCount%2 == 1
}

fun stripJson(jsonString: String, stripTrailingCommas: Boolean = false): String {
    // port from https://github.com/trapcodeio/go-strip-json-comments (MIT License, Copyright 2022 Mitch Allen)
    val notInsideComment = 0
    val singleComment = 1
    val multiComment = 2

    var isInsideString = false
    var isInsideComment = notInsideComment
    var offset = 0
    var buffer = ""
    var result = ""
    var commaIndex = -1

    var index = 0
    while (index < jsonString.length) {
        val currentCharacter = jsonString[index]
        var nextCharacter = '\u0000'
        if (index+1 < jsonString.length) {
            nextCharacter = jsonString[index+1]
        }
        if (isInsideComment == notInsideComment && currentCharacter == '"') {
            // Enter or exit string
            if (!isEscaped(jsonString, index)) {
                isInsideString = !isInsideString
            }
        }
        if (isInsideString) {
            index++
            continue
        }
        when {
            isInsideComment == notInsideComment && currentCharacter == '/' && nextCharacter == '/' -> {
                // Enter single-line comment
                buffer += jsonString.substring(offset, index)
                offset = index
                isInsideComment = singleComment
                index++
            }
            isInsideComment == singleComment && currentCharacter == '\r' && nextCharacter == '\n' -> {
                // Exit single-line comment via \r\n
                index++
                isInsideComment = notInsideComment
                offset = index
            }
            isInsideComment == singleComment && currentCharacter == '\n' -> {
                // Exit single-line comment via \n
                isInsideComment = notInsideComment
                offset = index
            }
            isInsideComment == notInsideComment && currentCharacter == '/' && nextCharacter == '*' -> {
                // Enter multiline comment
                buffer += jsonString.substring(offset, index)
                offset = index
                isInsideComment = multiComment
                index++
            }
            isInsideComment == multiComment && currentCharacter == '*' && nextCharacter == '/' -> {
                // Exit multiline comment
                index++
                isInsideComment = notInsideComment
                offset = index + 1
            }
            stripTrailingCommas && isInsideComment == notInsideComment -> {
                if (commaIndex != -1) {
                    if (currentCharacter == '}' || currentCharacter == ']') {
                        // Strip trailing comma
                        buffer += jsonString.substring(offset, index)
                        result += buffer.substring(1)
                        buffer = ""
                        offset = index
                        commaIndex = -1
                    } else if (currentCharacter != ' ' && currentCharacter != '\t' && currentCharacter != '\r' && currentCharacter != '\n') {
                        // Hit non-whitespace following a comma; comma is not trailing
                        buffer += jsonString.substring(offset, index)
                        offset = index
                        commaIndex = -1
                    }
                } else if (currentCharacter == ',') {
                    // Flush buffer prior to this point, and save new comma index
                    result += buffer + jsonString.substring(offset, index)
                    buffer = ""
                    offset = index
                    commaIndex = index
                }
            }
        }
        index++
    }
    val end = if (isInsideComment > notInsideComment) {
        ""
    } else {
        jsonString.substring(offset)
    }
    return result + buffer + end
}
