/******************************************************************************
 *                                                                            *
 * Copyright (C) 2024  dyhkwong                                               *
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

package io.nekohasekai.sagernet.database

import androidx.room.TypeConverter

class ListConverter {
    companion object {
        @TypeConverter
        @JvmStatic
        fun fromList(list: List<String>): String {
            return if (list.isEmpty()) {
                ""
            } else {
                list.joinToString(",")
            }
        }

        @TypeConverter
        @JvmStatic
        fun toList(str: String): List<String> {
            return if (str.isBlank()) {
                listOf()
            } else if (str.startsWith("[") && str.endsWith("]")) {
                // migrate from kapt to ksp
                str.removePrefix("[")
                    .removeSuffix("]")
                    .replace(" ", "")
                    .replace("\n", "")
                    .replace("\"", "")
                    .split(",")
            } else {
                str.split(",")
            }
        }
    }
}
