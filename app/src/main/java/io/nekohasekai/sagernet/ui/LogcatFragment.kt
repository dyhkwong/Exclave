/******************************************************************************
 * Copyright (C) 2021 by nekohasekai <contact-git@sekai.icu>                  *
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

import android.annotation.SuppressLint
import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.view.*
import androidx.appcompat.widget.Toolbar
import androidx.core.content.FileProvider
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.view.updatePadding
import io.nekohasekai.sagernet.BuildConfig
import io.nekohasekai.sagernet.R
import io.nekohasekai.sagernet.SagerNet
import io.nekohasekai.sagernet.databinding.LayoutLogcatBinding
import io.nekohasekai.sagernet.ktx.*
import io.nekohasekai.sagernet.utils.ColorUtils
import io.nekohasekai.sagernet.utils.CrashHandler
import java.io.BufferedReader
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.io.InputStreamReader
import java.nio.charset.StandardCharsets

class LogcatFragment : ToolbarFragment(R.layout.layout_logcat),
    Toolbar.OnMenuItemClickListener {

    lateinit var binding: LayoutLogcatBinding

    companion object {
        private const val MAX_BUFFERED_LINES = (1 shl 14) - 1
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        binding = LayoutLogcatBinding.bind(view)
        toolbar.setTitle(R.string.menu_log)

        toolbar.inflateMenu(R.menu.logcat_menu)
        toolbar.setOnMenuItemClickListener(this)

        ViewCompat.setOnApplyWindowInsetsListener(view.findViewById(R.id.logsScrollView)) { v, insets ->
            val bars = insets.getInsets(
                WindowInsetsCompat.Type.systemBars()
                        or WindowInsetsCompat.Type.displayCutout()
            )
            v.updatePadding(
                top = dp2px(8),
                left = bars.left + dp2px(8),
                right = bars.right + dp2px(8),
                bottom = bars.bottom + dp2px(64),
            )
            insets
        }

        (requireActivity() as? MainActivity)?.callback?.isEnabled = true

        runOnIoDispatcher {
            streamingLog()
        }
    }

    @SuppressLint("SetTextI18n")
    private suspend fun streamingLog() = onIoDispatcher {
        val format = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) "tag,color" else "tag"
        val filter = arrayOf(
            "AndroidRuntime:D",
            "ProxyInstance:D",
            "GuardedProcessPool:D",
            "RawUpdater:D",
            "SIP008Updater:D",
            "OpenOnlineConfigUpdater:D",
            "SubscriptionUpdater:D",
            "VpnService:D",
            "GoLog:D",
            "libcore:D",
            "v2ray-core:D",
            "su:D",
            "libnaive:D",
            "libbrook:D",
            "libhysteria:D",
            "libhysteria2:D",
            "libmieru:D",
            "libtuic5:D",
            "libtuic:D",
            "libtrojan-go:D",
            "libjuicity:D",
            "libshadowquic:D",
            "*:S",
        ).joinToString(",")

        val builder = ProcessBuilder(listOf("logcat", "-v", format, "-s", filter))
        builder.environment()["LC_ALL"] = "C"
        var process: Process? = null
        try {
            process = try {
                builder.start()
            } catch (_: Exception) {
                return@onIoDispatcher
            }

            val stdout = BufferedReader(
                InputStreamReader(process!!.inputStream, StandardCharsets.UTF_8)
            )
            val bufferedLogLines = arrayListOf<String>()

            var timeLastNotify = System.nanoTime()
            // The timeout is initially small so that the view gets populated immediately.
            var timeout = 1000000000L / 2


            while (true) {
                val line = stdout.readLine() ?: break
                bufferedLogLines.add(line)
                val timeNow = System.nanoTime()

                if (
                    bufferedLogLines.size < MAX_BUFFERED_LINES &&
                    (timeNow - timeLastNotify) < timeout && stdout.ready()
                ) continue

                // Increase the timeout after the initial view has something in it.
                timeout = 1000000000L * 5 / 2
                timeLastNotify = timeNow

                onMainDispatcher {
                    binding.logsTextView.append(
                        ColorUtils.ansiEscapeToSpannable(
                            binding.root.context,
                            bufferedLogLines.joinToString(
                                separator = "\n",
                                postfix = "\n"
                            )
                        )
                    )
                    bufferedLogLines.clear()
                    binding.logsScrollView.post {
                        val height = binding.logsTextView.height
                        binding.logsScrollView.smoothScrollTo(0, height)
                    }
                }
            }
        } finally {
            process?.destroy()
        }
    }

    override fun onMenuItemClick(item: MenuItem): Boolean {
        when (item.itemId) {
            R.id.action_clear_logcat -> {
                runOnIoDispatcher {
                    val command = listOf("logcat", "-c")
                    val process = ProcessBuilder(command).start()
                    process.waitFor()
                    onMainDispatcher {
                        binding.logsTextView.text = ""
                    }
                }
            }
            R.id.action_copy_logcat -> {
                val text = binding.logsTextView.text.toString()
                if (text.isNotEmpty()) {
                    runOnDefaultDispatcher {
                        onMainDispatcher {
                            SagerNet.trySetPrimaryClip(text)
                        }
                    }
                }
            }
            R.id.action_send_logcat -> {
                val context = requireContext()
                runOnDefaultDispatcher {
                    val logFile = File.createTempFile("Exclave ",
                        ".log",
                        File(app.cacheDir, "log").also { it.mkdirs() })

                    var report = CrashHandler.buildReportHeader()

                    report += "Logcat: \n\n"

                    logFile.writeText(report)

                    try {
                        Runtime.getRuntime().exec(arrayOf("logcat", "-d")).inputStream.use(
                            FileOutputStream(
                                logFile, true
                            )
                        )
                    } catch (e: IOException) {
                        Logs.w(e)
                        logFile.appendText("Export logcat error: " + CrashHandler.formatThrowable(e))
                    }

                    context.startActivity(
                        Intent.createChooser(
                            Intent(Intent.ACTION_SEND).setType("text/x-log")
                                .setFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                                .putExtra(
                                    Intent.EXTRA_STREAM, FileProvider.getUriForFile(
                                        context, BuildConfig.APPLICATION_ID + ".cache", logFile
                                    )
                                ), context.getString(androidx.appcompat.R.string.abc_shareactionprovider_share_with)
                        )
                    )
                }
            }
        }
        return true
    }
}