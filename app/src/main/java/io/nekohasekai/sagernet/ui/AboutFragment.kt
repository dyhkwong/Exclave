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

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.PowerManager
import android.provider.Settings
import android.text.util.Linkify
import android.view.View
import androidx.activity.result.component1
import androidx.activity.result.component2
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.view.updatePadding
import androidx.recyclerview.widget.RecyclerView
import com.danielstone.materialaboutlibrary.MaterialAboutFragment
import com.danielstone.materialaboutlibrary.items.MaterialAboutActionItem
import com.danielstone.materialaboutlibrary.model.MaterialAboutCard
import com.danielstone.materialaboutlibrary.model.MaterialAboutList
import io.nekohasekai.sagernet.BuildConfig
import io.nekohasekai.sagernet.R
import io.nekohasekai.sagernet.database.DataStore
import io.nekohasekai.sagernet.databinding.LayoutAboutBinding
import io.nekohasekai.sagernet.fmt.PluginEntry
import io.nekohasekai.sagernet.ktx.*
import io.nekohasekai.sagernet.plugin.PluginManager
import libcore.Libcore

class AboutFragment : ToolbarFragment(R.layout.layout_about) {

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        val binding = LayoutAboutBinding.bind(view)

        toolbar.setTitle(R.string.menu_about)
        ViewCompat.setOnApplyWindowInsetsListener(toolbar) { v, insets ->
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
        ViewCompat.setOnApplyWindowInsetsListener(view.findViewById(R.id.layout_about)) { v, insets ->
            val bars = insets.getInsets(
                WindowInsetsCompat.Type.systemBars()
                        or WindowInsetsCompat.Type.displayCutout()
            )
            v.updatePadding(
                left = bars.left,
                right = bars.right,
                bottom = bars.bottom,
            )
            WindowInsetsCompat.CONSUMED
        }

        parentFragmentManager.beginTransaction()
            .replace(R.id.about_fragment_holder, AboutContent())
            .commitAllowingStateLoss()

        (requireActivity() as? MainActivity)?.callback?.isEnabled = true

        runOnDefaultDispatcher {
            onMainDispatcher {
                binding.license.text = "Copyright (C) 2023-2025 by dyhkwong\n" +
                        "Copyright (C) 2021 by nekohasekai <contact-sagernet@sekai.icu>\n\n" +
                        "This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3.\n\n" +
                        "This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.\n\n" +
                        "You should have received a copy of the GNU General Public License along with this program. If not, see <http://www.gnu.org/licenses/>."
                Linkify.addLinks(binding.license, Linkify.EMAIL_ADDRESSES or Linkify.WEB_URLS)
            }
        }
    }

    class AboutContent : MaterialAboutFragment() {

        val requestIgnoreBatteryOptimizations = registerForActivityResult(
            ActivityResultContracts.StartActivityForResult()
        ) { (resultCode, _) ->
            parentFragmentManager.beginTransaction()
                .replace(R.id.about_fragment_holder, AboutContent())
                .commitAllowingStateLoss()
        }

        override fun getMaterialAboutList(activityContext: Context?): MaterialAboutList {
            try {
                requireContext()
            } catch (e: Exception) {
                Logs.w(e)
                return MaterialAboutList.Builder().build()
            }

            return MaterialAboutList.Builder()
                .addCard(MaterialAboutCard.Builder()
                    .outline(false)
                    .addItem(MaterialAboutActionItem.Builder()
                        .icon(R.drawable.ic_baseline_update_24)
                        .text(R.string.app_version)
                        .subText(BuildConfig.VERSION_NAME)
                        .setOnClickAction {
                            requireContext().launchCustomTab(
                                "https://github.com/dyhkwong/Exclave/releases"
                            )
                        }
                        .setOnLongClickAction {
                            DataStore.enableDebug = !DataStore.enableDebug
                        }
                        .build())
                    .addItem(MaterialAboutActionItem.Builder()
                        .icon(R.drawable.ic_baseline_airplanemode_active_24)
                        .text(getString(R.string.version_x, "v2ray-core"))
                        .subText("v" + Libcore.getV2RayVersion())
                        .setOnClickAction {
                            requireContext().launchCustomTab(
                                "https://github.com/dyhkwong/v2ray-core/tree/dev-sagernet"
                            )
                        }
                        .build())
                    .apply {
                        val m = enumValues<PluginEntry>().associateBy { it.pluginId }
                        for (plugin in PluginManager.fetchPlugins()) {
                            if (!m.containsKey(plugin.id)) continue
                            try {
                                addItem(MaterialAboutActionItem.Builder()
                                    .icon(R.drawable.ic_baseline_nfc_24)
                                    .text(getString(R.string.version_x, plugin.id))
                                    .subText("v" + plugin.versionName)
                                    .setOnClickAction {
                                        startActivity(Intent().apply {
                                            action = Settings.ACTION_APPLICATION_DETAILS_SETTINGS
                                            data = Uri.fromParts(
                                                "package", plugin.packageName, null
                                            )
                                        })
                                    }
                                    .build())
                            } catch (e: Exception) {
                                Logs.w(e)
                            }
                        }
                    }
                    .apply {
                        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                            val pm = app.getSystemService(Context.POWER_SERVICE) as PowerManager
                            if (!pm.isIgnoringBatteryOptimizations(app.packageName)) {
                                addItem(MaterialAboutActionItem.Builder()
                                    .icon(R.drawable.ic_baseline_running_with_errors_24)
                                    .text(R.string.ignore_battery_optimizations)
                                    .subText(R.string.ignore_battery_optimizations_sum)
                                    .setOnClickAction {
                                        requestIgnoreBatteryOptimizations.launch(
                                            Intent(
                                                Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS,
                                                Uri.parse("package:${app.packageName}")
                                            )
                                        )
                                    }
                                    .build())
                            }
                        }
                        addItem(MaterialAboutActionItem.Builder()
                            .icon(R.drawable.ic_baseline_card_giftcard_24)
                            .text(R.string.donate_to_original_author)
                            .subText(R.string.donate_info)
                            .setOnClickAction {
                                requireContext().launchCustomTab(
                                    "https://sekai.icu/sponsors/"
                                )
                            }
                            .build())
                    }
                    .build())
                .addCard(MaterialAboutCard.Builder()
                    .outline(false)
                    .title(R.string.project)
                    .addItem(MaterialAboutActionItem.Builder()
                        .icon(R.drawable.ic_baseline_sanitizer_24)
                        .text(R.string.github)
                        .setOnClickAction {
                            requireContext().launchCustomTab(
                                "https://github.com/dyhkwong/Exclave"

                            )
                        }
                        .build())
                    .build())
                .build()

        }

        override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
            super.onViewCreated(view, savedInstanceState)

            view.findViewById<RecyclerView>(com.danielstone.materialaboutlibrary.R.id.mal_recyclerview).apply {
                overScrollMode = RecyclerView.OVER_SCROLL_NEVER
            }
        }

    }

}