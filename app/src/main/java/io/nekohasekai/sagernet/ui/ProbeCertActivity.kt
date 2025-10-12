/******************************************************************************
 *                                                                            *
 * Copyright (C) 2024 by dyhkwong                                             *
 * Copyright (C) 2024 by HystericalDragons                                    *
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

import android.content.ClipData
import android.os.Bundle
import android.view.View
import android.widget.AdapterView
import androidx.appcompat.app.AlertDialog
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.view.isVisible
import androidx.core.view.updatePadding
import androidx.core.widget.doAfterTextChanged
import io.nekohasekai.sagernet.R
import io.nekohasekai.sagernet.SagerNet
import io.nekohasekai.sagernet.database.DataStore
import io.nekohasekai.sagernet.databinding.LayoutProbeCertBinding
import io.nekohasekai.sagernet.ktx.Logs
import io.nekohasekai.sagernet.ktx.onMainDispatcher
import io.nekohasekai.sagernet.ktx.runOnDefaultDispatcher
import libcore.Libcore

class ProbeCertActivity : ThemedActivity() {

    private lateinit var binding: LayoutProbeCertBinding

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        binding = LayoutProbeCertBinding.inflate(layoutInflater)
        setContentView(binding.root)

        ViewCompat.setOnApplyWindowInsetsListener(binding.root) { v, insets ->
            val ime = insets.getInsets(WindowInsetsCompat.Type.ime())
            v.updatePadding(
                bottom = ime.bottom,
            )
            insets
        }
        ViewCompat.setOnApplyWindowInsetsListener(findViewById(R.id.main_layout)) { v, insets ->
            val bars = insets.getInsets(
                WindowInsetsCompat.Type.systemBars()
                        or WindowInsetsCompat.Type.displayCutout()
            )
            v.updatePadding(
                left = bars.left,
                right = bars.right,
                bottom = bars.bottom,
            )
            insets
        }
        setSupportActionBar(findViewById(R.id.toolbar))
        supportActionBar?.apply {
            setTitle(R.string.probe_cert)
            setDisplayHomeAsUpEnabled(true)
            setHomeAsUpIndicator(R.drawable.baseline_arrow_back_24)
        }

        binding.probeCertServer.setText("example.com")
        binding.probeCertServerPort.setText("443")
        binding.probeCertServerName.setText("example.com")
        binding.probeCertServer.doAfterTextChanged { text ->
            binding.probeCertServerName.setText(text)
        }
        binding.probeCertAlpn.setText("h2,http/1.1")
        binding.probeCertProtocol.onItemSelectedListener = object : AdapterView.OnItemSelectedListener {
            override fun onItemSelected(
                parent: AdapterView<*>?, view: View?, position: Int, id: Long
            ) {
                when (position) {
                    0 -> binding.probeCertAlpn.setText("h2,http/1.1")
                    1 -> binding.probeCertAlpn.setText("h3")
                    else -> error("unknown protocol")
                }
            }
            override fun onNothingSelected(parent: AdapterView<*>?) {
            }
        }

        binding.probeCert.setOnClickListener {
            probeCert()
        }

        binding.certificate.doAfterTextChanged { text ->
            try {
                binding.certHash.text = when (binding.certHashType.selectedItemPosition) {
                    0 -> Libcore.calculatePEMCertSHA256Hash(text.toString())
                    1 -> Libcore.calculatePEMCertPublicKeySHA256Hash(text.toString())
                    2 -> Libcore.calculatePEMCertChainSHA256Hash(text.toString())
                    else -> error("impossible")
                }
            } catch (_: Exception) {
                binding.certHash.text = ""
            }
        }
        binding.certHashType.onItemSelectedListener = object : AdapterView.OnItemSelectedListener {
            override fun onItemSelected(
                parent: AdapterView<*>?, view: View?, position: Int, id: Long
            ) {
                try {
                    val certificate = binding.certificate.text.toString()
                    val certHash = when (position) {
                        0 -> Libcore.calculatePEMCertSHA256Hash(certificate)
                        1 -> Libcore.calculatePEMCertPublicKeySHA256Hash(certificate)
                        2 -> Libcore.calculatePEMCertChainSHA256Hash(certificate)
                        else -> error("impossible")
                    }
                    binding.certHash.text = certHash
                } catch (_: Exception) {
                    binding.certHash.text = ""
                }
            }
            override fun onNothingSelected(parent: AdapterView<*>?) {
            }
        }
        binding.certHash.setOnClickListener {
            try {
                val clipData = ClipData.newPlainText("hash", binding.certHash.text)
                SagerNet.clipboard.setPrimaryClip(clipData)
            } catch (e: Exception) {
                Logs.w(e)
            }
        }
    }

    private fun probeCert() {
        binding.waitLayout.isVisible = true
        runOnDefaultDispatcher {
            val result = Libcore.probeCert(
                binding.probeCertServer.text.toString(),
                binding.probeCertServerPort.text.toString().toInt(),
                binding.probeCertServerName.text.toString(),
                binding.probeCertAlpn.text.toString(),
                when (binding.probeCertProtocol.selectedItemPosition) {
                    0 -> "tls"
                    1 -> "quic"
                    else -> error("impossible")
                },
                SagerNet.started && DataStore.startedProfile > 0,
                DataStore.socksPort
            )
            onMainDispatcher {
                binding.waitLayout.isVisible = false
                if (result.error.isNotEmpty()) {
                    binding.certificate.setText("")
                    AlertDialog.Builder(this@ProbeCertActivity)
                        .setTitle(R.string.error_title)
                        .setMessage(result.error)
                        .setPositiveButton(android.R.string.ok) { _, _ -> }
                        .setOnCancelListener { finish() }
                        .runCatching { show() }
                } else {
                    binding.certificate.setText(result.cert)
                    if (result.verifyError.isNotEmpty()) {
                        AlertDialog.Builder(this@ProbeCertActivity)
                            .setTitle(R.string.error_title)
                            .setMessage(result.verifyError)
                            .setPositiveButton(android.R.string.ok) { _, _ -> }
                            .setOnCancelListener { finish() }
                            .runCatching { show() }
                    }
                }
            }
        }
    }

}
