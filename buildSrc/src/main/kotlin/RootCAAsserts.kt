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

import cn.hutool.crypto.digest.DigestUtil
import cn.hutool.http.HttpUtil
import org.gradle.api.Project
import java.io.File

fun Project.downloadRootCAList() {
    val assets = File(projectDir, "src/main/assets")
    val pem = File(assets, "mozilla_included.pem")
    val pemSha256 = File(assets, "mozilla_included.pem.sha256sum")
    val data = HttpUtil.get("https://ccadb.my.salesforce-sites.com/mozilla/IncludedRootsPEMTxt?TrustBitsInclude=Websites")
        ?: error("download mozilla_included.pem failed")
    val dataSha256 = DigestUtil.sha256Hex(data)
    pem.writeText(data)
    pemSha256.writeText(dataSha256)
}
