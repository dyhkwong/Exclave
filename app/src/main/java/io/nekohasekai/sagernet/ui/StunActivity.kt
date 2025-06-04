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

import android.os.Bundle
import android.widget.ArrayAdapter
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.widget.ListPopupWindow
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.view.isVisible
import androidx.core.view.updatePadding
import io.nekohasekai.sagernet.R
import io.nekohasekai.sagernet.SagerNet
import io.nekohasekai.sagernet.database.DataStore
import io.nekohasekai.sagernet.databinding.LayoutStunBinding
import io.nekohasekai.sagernet.ktx.PUBLIC_STUN_SERVERS
import io.nekohasekai.sagernet.ktx.listByLineOrComma
import io.nekohasekai.sagernet.ktx.onMainDispatcher
import io.nekohasekai.sagernet.ktx.runOnDefaultDispatcher
import io.noties.markwon.Markwon
import libcore.Libcore

class StunActivity : ThemedActivity() {

    private lateinit var binding: LayoutStunBinding
    private val markwon by lazy { Markwon.create(this) }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        binding = LayoutStunBinding.inflate(layoutInflater)
        setContentView(binding.root)

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
            insets
        }
        ViewCompat.setOnApplyWindowInsetsListener(findViewById(R.id.result_layout)) { v, insets ->
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
            setTitle(R.string.stun_test)
            setDisplayHomeAsUpEnabled(true)
            setHomeAsUpIndicator(R.drawable.baseline_arrow_back_24)
        }


        val list = if (DataStore.stunServers.isEmpty()) {
            PUBLIC_STUN_SERVERS
        } else {
            DataStore.stunServers.listByLineOrComma().toTypedArray()
        }

        binding.natStunServer.setText(if (DataStore.stunServers.isEmpty()) list.random() else list[0])
        binding.natStunServer.setOnClickListener {
            val listPopupWindow = ListPopupWindow(this)
            listPopupWindow.setAdapter(
                ArrayAdapter(this, android.R.layout.simple_list_item_1, list)
            )
            listPopupWindow.setOnItemClickListener { _, _, i, _ ->
                binding.natStunServer.setText(list[i])
                listPopupWindow.dismiss()
            }
            listPopupWindow.anchorView = binding.natStunServer
            listPopupWindow.show()
        }
        binding.stunRB.isChecked = true
        binding.stunTest.setOnClickListener {
            when {
                binding.stunRB.isChecked -> doTest()
                binding.stunLegacyRB.isChecked -> doLegacyTest()
            }
        }
        binding.natMappingBehaviourCard.isVisible = false
        binding.natFilteringBehaviourCard.isVisible = false
        binding.natTypeCard.isVisible = false
        binding.natExternalAddressCard.isVisible = false
    }

    fun doTest() {
        binding.waitLayout.isVisible = true
        binding.resultLayout.isVisible = false
        runOnDefaultDispatcher {
            val result = Libcore.stunTest(binding.natStunServer.text.toString(),
                SagerNet.started && DataStore.startedProfile > 0,
                DataStore.socksPort
            )
            onMainDispatcher {
                if (result.error.isNotEmpty()) {
                    AlertDialog.Builder(this@StunActivity)
                        .setTitle(R.string.error_title)
                        .setMessage(result.error)
                        .setPositiveButton(android.R.string.ok) { _, _ -> }
                        .setOnCancelListener { finish() }
                        .runCatching { show() }
                }
                binding.waitLayout.isVisible = false
                binding.resultLayout.isVisible = true
                markwon.setMarkdown(binding.natMappingBehaviour, result.natMapping)
                markwon.setMarkdown(binding.natFilteringBehaviour, result.natFiltering)
                binding.natMappingBehaviourCard.isVisible = true
                binding.natFilteringBehaviourCard.isVisible = true
                binding.natTypeCard.isVisible = false
                binding.natExternalAddressCard.isVisible = false
            }
        }
    }

    fun doLegacyTest() {
        binding.waitLayout.isVisible = true
        binding.resultLayout.isVisible = false
        runOnDefaultDispatcher {
            val result = Libcore.stunLegacyTest(binding.natStunServer.text.toString(),
                SagerNet.started && DataStore.startedProfile > 0,
                DataStore.socksPort
            )
            onMainDispatcher {
                if (result.error.isNotEmpty()) {
                    AlertDialog.Builder(this@StunActivity)
                        .setTitle(R.string.error_title)
                        .setMessage(result.error)
                        .setPositiveButton(android.R.string.ok) { _, _ -> }
                        .setOnCancelListener { finish() }
                        .runCatching { show() }
                }
                binding.waitLayout.isVisible = false
                binding.resultLayout.isVisible = true
                markwon.setMarkdown(binding.natType, result.natType)
                markwon.setMarkdown(binding.natExternalAddress, result.host)
                binding.natMappingBehaviourCard.isVisible = false
                binding.natFilteringBehaviourCard.isVisible = false
                binding.natTypeCard.isVisible = true
                binding.natExternalAddressCard.isVisible = true
            }
        }
    }

}