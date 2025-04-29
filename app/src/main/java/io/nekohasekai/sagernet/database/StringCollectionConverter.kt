package io.nekohasekai.sagernet.database

import androidx.room.TypeConverter

class StringCollectionConverter {
    companion object {
        @TypeConverter
        @JvmStatic
        fun fromSet(set: Set<String>): String = if (set.isEmpty()) {
            ""
        } else {
            set.joinToString(",")
        }
        @TypeConverter
        @JvmStatic
        fun toSet(str: String): Set<String> = if (str.isBlank()) {
            emptySet()
        } else {
            str.split(",").toSet()
        }
    }
}

