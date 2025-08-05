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

package io.nekohasekai.sagernet.ui

import androidx.camera.core.ImageAnalysis
import androidx.camera.core.ImageProxy
import com.google.zxing.BinaryBitmap
import com.google.zxing.NotFoundException
import com.google.zxing.RGBLuminanceSource
import com.google.zxing.common.GlobalHistogramBinarizer
import com.google.zxing.qrcode.QRCodeReader

class ZxingQRCodeAnalyzer(
    private val onSuccess: ((String) -> Unit),
    private val onFailure: ((Exception) -> Unit),
) : ImageAnalysis.Analyzer {

    private val qrCodeReader = QRCodeReader()
    override fun analyze(image: ImageProxy) {
        try {
            val bitmap = image.toBitmap()
            val intArray = IntArray(bitmap.getWidth() * bitmap.getHeight())
            bitmap.getPixels(
                intArray,
                0,
                bitmap.getWidth(),
                0,
                0,
                bitmap.getWidth(),
                bitmap.getHeight()
            )
            val source = RGBLuminanceSource(bitmap.getWidth(), bitmap.getHeight(), intArray)
            val result = try {
                qrCodeReader.decode(BinaryBitmap(GlobalHistogramBinarizer(source)))
            } catch (e: NotFoundException) {
                try {
                    qrCodeReader.decode(BinaryBitmap(GlobalHistogramBinarizer(source.invert())))
                } catch (ignore: NotFoundException) {
                    return
                }
            }
            onSuccess(result.text)
        } catch (_: Exception) {
        } finally {
            image.close()
        }
    }
}