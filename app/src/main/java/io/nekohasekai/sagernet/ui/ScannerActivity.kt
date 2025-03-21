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

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.content.pm.ShortcutManager
import android.graphics.ImageDecoder
import android.os.Build
import android.os.Bundle
import android.provider.MediaStore
import android.view.KeyEvent
import android.view.Menu
import android.view.MenuItem
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.camera.core.*
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.core.content.ContextCompat
import androidx.core.content.getSystemService
import androidx.core.view.ViewCompat
import androidx.core.view.WindowCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.view.updatePadding
import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.NotFoundException
import com.google.zxing.RGBLuminanceSource
import com.google.zxing.common.GlobalHistogramBinarizer
import com.google.zxing.qrcode.QRCodeReader
import io.nekohasekai.sagernet.R
import io.nekohasekai.sagernet.database.DataStore
import io.nekohasekai.sagernet.database.ProfileManager
import io.nekohasekai.sagernet.databinding.LayoutScannerBinding
import io.nekohasekai.sagernet.group.RawUpdater
import io.nekohasekai.sagernet.ktx.*
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import androidx.core.net.toUri
import cn.hutool.core.lang.Validator.isUrl
import libcore.Libcore


class ScannerActivity : ThemedActivity() {

    private lateinit var analysisExecutor: ExecutorService
    private lateinit var binding: LayoutScannerBinding

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)


        setTitle(R.string.add_profile_methods_scan_qr_code)

        /*if (Build.VERSION.SDK_INT != Build.VERSION_CODES.O) {
            requestedOrientation = ActivityInfo.SCREEN_ORIENTATION_PORTRAIT
        }*/
        if (Build.VERSION.SDK_INT >= 25) getSystemService<ShortcutManager>()!!.reportShortcutUsed("scan")

        binding = LayoutScannerBinding.inflate(layoutInflater)
        setContentView(binding.root)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R && Build.VERSION.SDK_INT <= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            WindowCompat.setDecorFitsSystemWindows(window, false)
        }
        ViewCompat.setOnApplyWindowInsetsListener(findViewById(R.id.toolbar)) { v, insets ->
            val bars = insets.getInsets(
                WindowInsetsCompat.Type.systemBars()
                        or WindowInsetsCompat.Type.displayCutout()
            )
            v.updatePadding(
                top = bars.top,
                left = bars.left,
                right = bars.right,
            )
            WindowInsetsCompat.CONSUMED
        }
        setSupportActionBar(findViewById(R.id.toolbar))
        supportActionBar?.apply {
            setDisplayHomeAsUpEnabled(true)
            setHomeAsUpIndicator(R.drawable.ic_navigation_close)
        }

        analysisExecutor = Executors.newSingleThreadExecutor()
        binding.previewView.implementationMode = PreviewView.ImplementationMode.COMPATIBLE
        binding.previewView.previewStreamState.observe(this) {
            if (it === PreviewView.StreamState.STREAMING) {
                binding.previewView.implementationMode = PreviewView.ImplementationMode.PERFORMANCE
            }
        }
        if (ContextCompat.checkSelfPermission(
                this, Manifest.permission.CAMERA
            ) == PackageManager.PERMISSION_GRANTED
        ) {
            startCamera()
        } else {
            requestPermissionLauncher.launch(Manifest.permission.CAMERA)
        }
    }

    private val requestPermissionLauncher =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) { isGranted: Boolean ->
            if (isGranted) {
                startCamera()
            } else {
                setResult(RESULT_CANCELED)
                finish()
            }
        }

    private lateinit var imageAnalysis: ImageAnalysis
    private lateinit var imageAnalyzer: ImageAnalysis.Analyzer
    private val onSuccess: (String) -> Unit = { rawValue: String ->
        imageAnalysis.clearAnalyzer()
        onSuccess(rawValue)

    }

    private lateinit var cameraProvider: ProcessCameraProvider
    private lateinit var cameraPreview: Preview
    private lateinit var camera: Camera

    private fun startCamera() {
        val cameraProviderFuture = try {
            ProcessCameraProvider.getInstance(this)
        } catch (e: Exception) {
            fatalError(e)
            return
        }
        cameraProviderFuture.addListener({
            cameraProvider = try {
                cameraProviderFuture.get()
            } catch (e: Exception) {
                fatalError(e)
                return@addListener
            }

            cameraPreview = Preview.Builder().build()
                .also { it.setSurfaceProvider(binding.previewView.surfaceProvider) }
            imageAnalysis = ImageAnalysis.Builder().build()
            imageAnalyzer = ZxingQRCodeAnalyzer(onSuccess, fatalError)
            imageAnalysis.setAnalyzer(analysisExecutor, imageAnalyzer)
            cameraProvider.unbindAll()

            try {
                camera = cameraProvider.bindToLifecycle(
                    this, CameraSelector.DEFAULT_BACK_CAMERA, cameraPreview, imageAnalysis
                )
            } catch (e: Exception) {
                fatalError(e)
            }
        }, ContextCompat.getMainExecutor(this))
    }

    private val fatalError: (Exception?) -> Unit = {
        if (it != null) Logs.w(it)
        runOnMainDispatcher {
            Toast.makeText(app, R.string.action_import_err, Toast.LENGTH_SHORT).show()
        }
    }

    private fun onSuccess(value: String): Boolean {
        finish()
        runOnDefaultDispatcher {
            try {
                val results = RawUpdater.parseRaw(value)
                if (results.isNullOrEmpty()) {
                    if (isUrl(value)) {
                        val builder = Libcore.newURL("exclave").apply {
                            host = "subscription"
                        }
                        builder.addQueryParameter("url", value)
                        startActivity(Intent(this@ScannerActivity, MainActivity::class.java).apply {
                            action = Intent.ACTION_VIEW
                            data = builder.string.toUri()
                        })
                    } else {
                        fatalError(null)
                    }
                } else {
                    val currentGroupId = DataStore.selectedGroupForImport()
                    if (DataStore.selectedGroup != currentGroupId) {
                        DataStore.selectedGroup = currentGroupId
                    }

                    for (profile in results) {
                        ProfileManager.createProfile(currentGroupId, profile)
                    }
                }
            } catch (e: SubscriptionFoundException) {
                startActivity(Intent(this@ScannerActivity, MainActivity::class.java).apply {
                    action = Intent.ACTION_VIEW
                    data = e.link.toUri()
                })
            } catch (e: Exception) {
                fatalError(e)
            }
        }
        return true
    }

    private val importCodeFile =
        registerForActivityResult(ActivityResultContracts.GetMultipleContents()) {
            runOnDefaultDispatcher {
                try {
                    it.forEachTry { uri ->
                        val bitmap = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                            ImageDecoder.decodeBitmap(
                                ImageDecoder.createSource(
                                    contentResolver, uri
                                )
                            ) { decoder, _, _ ->
                                decoder.allocator = ImageDecoder.ALLOCATOR_SOFTWARE
                                decoder.isMutableRequired = true
                            }
                        } else {
                            @Suppress("DEPRECATION") MediaStore.Images.Media.getBitmap(
                                contentResolver, uri
                            )
                        }
                        val intArray = IntArray(bitmap.width * bitmap.height)
                        bitmap.getPixels(
                            intArray,
                            0,
                            bitmap.width,
                            0,
                            0,
                            bitmap.width,
                            bitmap.height
                        )

                        val source = RGBLuminanceSource(bitmap.width, bitmap.height, intArray)
                        val qrReader = QRCodeReader()
                        try {
                            val result = try {
                                qrReader.decode(
                                    BinaryBitmap(GlobalHistogramBinarizer(source)),
                                    mapOf(DecodeHintType.TRY_HARDER to true)
                                )
                            } catch (e: NotFoundException) {
                                qrReader.decode(
                                    BinaryBitmap(GlobalHistogramBinarizer(source.invert())),
                                    mapOf(DecodeHintType.TRY_HARDER to true)
                                )
                            }

                            val results = RawUpdater.parseRaw(result.text ?: "")

                            if (!results.isNullOrEmpty()) {
                                onMainDispatcher {
                                    finish()
                                    runOnDefaultDispatcher {
                                        val currentGroupId = DataStore.selectedGroupForImport()
                                        if (DataStore.selectedGroup != currentGroupId) {
                                            DataStore.selectedGroup = currentGroupId
                                        }

                                        for (profile in results) {
                                            ProfileManager.createProfile(currentGroupId, profile)
                                        }
                                    }
                                }
                            } else {
                                if (isUrl(result.text)) {
                                    val builder = Libcore.newURL("exclave").apply {
                                        host = "subscription"
                                    }
                                    builder.addQueryParameter("url", result.text)
                                    startActivity(Intent(this@ScannerActivity, MainActivity::class.java).apply {
                                        action = Intent.ACTION_VIEW
                                        data = builder.string.toUri()
                                    })
                                    finish()
                                } else {
                                    Toast.makeText(app, R.string.action_import_err, Toast.LENGTH_SHORT).show()
                                }
                            }
                        } catch (e: SubscriptionFoundException) {
                            startActivity(Intent(this@ScannerActivity, MainActivity::class.java).apply {
                                action = Intent.ACTION_VIEW
                                data = e.link.toUri()
                            })
                            finish()
                        } catch (e: Throwable) {
                            Logs.w(e)
                            onMainDispatcher {
                                Toast.makeText(app, R.string.action_import_err, Toast.LENGTH_SHORT).show()
                            }
                        }
                    }
                } catch (e: Exception) {
                    Logs.w(e)

                    onMainDispatcher {
                        Toast.makeText(app, e.readableMessage, Toast.LENGTH_LONG).show()
                    }
                }
            }
        }

    /**
     * See also: https://stackoverflow.com/a/31350642/2245107
     */
    override fun shouldUpRecreateTask(targetIntent: Intent?): Boolean {
        return super.shouldUpRecreateTask(targetIntent) || isTaskRoot
    }

    override fun onKeyDown(keyCode: Int, event: KeyEvent?): Boolean {
        return binding.previewView.onKeyDown(keyCode, event) || super.onKeyDown(keyCode, event)
    }

    override fun onCreateOptionsMenu(menu: Menu?): Boolean {
        menuInflater.inflate(R.menu.scanner_menu, menu)
        return true
    }

    // Every time camera.cameraInfo.cameraSelector will get different value,
    // so useFront used to record it.
    // sfa use select to resolve it.
    private var useFront = false
    private lateinit var flash: MenuItem

    private fun resetFlash() {
        flash.setIcon(R.drawable.ic_action_flight_on)
        flash.setTitle(R.string.action_flash_on)
        flash.isVisible = true
    }

    override fun onPrepareOptionsMenu(menu: Menu): Boolean {
        flash = menu.findItem(R.id.action_flash)
        return super.onPrepareOptionsMenu(menu)
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        when (item.itemId) {
            R.id.action_import_file -> {
                startFilesForResult(importCodeFile, "image/*")
            }

            R.id.action_flash -> {
                val enableFlash = camera.cameraInfo.torchState.value == TorchState.ON
                camera.cameraControl.enableTorch(!enableFlash)
                if (enableFlash) {
                    item.setIcon(R.drawable.ic_action_flight_on)
                    item.setTitle(R.string.action_flash_on)
                } else {
                    item.setIcon(R.drawable.ic_action_flight_off)
                    item.setTitle(R.string.action_flash_off)
                }
            }

            // Switch front or back camera.
            R.id.action_camera_switch -> {
                useFront = !useFront
                camera.cameraControl.enableTorch(false)
                val cameraSelector = if (useFront) {
                    flash.isVisible = false

                    CameraSelector.DEFAULT_FRONT_CAMERA
                } else {
                    resetFlash()

                    CameraSelector.DEFAULT_BACK_CAMERA
                }
                cameraProvider.unbindAll()
                try {
                    camera = cameraProvider.bindToLifecycle(
                        this,
                        cameraSelector,
                        cameraPreview,
                        imageAnalysis
                    )
                } catch (e: Exception) {
                    fatalError(e)
                }
            }

            else -> return super.onOptionsItemSelected(item)
        }

        return true
    }
}