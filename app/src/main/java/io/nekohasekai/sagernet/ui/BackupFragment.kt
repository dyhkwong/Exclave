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

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.os.Parcel
import android.os.Parcelable
import android.provider.OpenableColumns
import android.view.View
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.core.content.FileProvider
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.view.isVisible
import androidx.core.view.updatePadding
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.google.gson.GsonBuilder
import com.google.gson.JsonArray
import com.google.gson.JsonObject
import com.jakewharton.processphoenix.ProcessPhoenix
import io.nekohasekai.sagernet.BuildConfig
import io.nekohasekai.sagernet.R
import io.nekohasekai.sagernet.SagerNet
import io.nekohasekai.sagernet.database.*
import io.nekohasekai.sagernet.database.preference.KeyValuePair
import io.nekohasekai.sagernet.database.preference.PublicDatabase
import io.nekohasekai.sagernet.databinding.LayoutBackupBinding
import io.nekohasekai.sagernet.databinding.LayoutImportBinding
import io.nekohasekai.sagernet.databinding.LayoutProgressBinding
import io.nekohasekai.sagernet.ktx.*
import java.io.File
import kotlin.io.encoding.Base64

class BackupFragment : NamedFragment(R.layout.layout_backup) {

    var content = ""
    private val exportSettings = registerForActivityResult(ActivityResultContracts.CreateDocument()) { data ->
        if (data != null) {
            runOnDefaultDispatcher {
                try {
                    requireActivity().contentResolver.openOutputStream(
                        data
                    )!!.bufferedWriter().use {
                        it.write(content)
                    }
                    onMainDispatcher {
                        snackbar(getString(R.string.action_export_msg)).show()
                    }
                } catch (e: Exception) {
                    Logs.w(e)
                    onMainDispatcher {
                        snackbar(e.readableMessage).show()
                    }
                }

            }
        }
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        val binding = LayoutBackupBinding.bind(view)
        ViewCompat.setOnApplyWindowInsetsListener(binding.root) { v, insets ->
            val bars = insets.getInsets(
                WindowInsetsCompat.Type.systemBars()
                        or WindowInsetsCompat.Type.displayCutout()
            )
            v.updatePadding(
                left = bars.left,
                right = bars.right,
                bottom = bars.bottom + dp2px(64),
            )
            insets
        }
        binding.actionExport.setOnClickListener {
            runOnDefaultDispatcher {
                content = doBackup(
                    binding.backupConfigurations.isChecked,
                    binding.backupRules.isChecked,
                    binding.backupSettings.isChecked
                )
                onMainDispatcher {
                    startFilesForResult(
                        exportSettings, "exclave_backup_${System.currentTimeMillis()}.json"
                    )
                }
            }
        }

        binding.actionShare.setOnClickListener {
            runOnDefaultDispatcher {
                content = doBackup(
                    binding.backupConfigurations.isChecked,
                    binding.backupRules.isChecked,
                    binding.backupSettings.isChecked
                )
                app.cacheDir.mkdirs()
                val cacheFile = File(
                    app.cacheDir, "exclave_backup_${System.currentTimeMillis()}.json"
                )
                cacheFile.writeText(content)
                onMainDispatcher {
                    startActivity(
                        Intent.createChooser(
                            Intent(Intent.ACTION_SEND).setType("application/json")
                                .setFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                                .putExtra(
                                    Intent.EXTRA_STREAM, FileProvider.getUriForFile(
                                        app, BuildConfig.APPLICATION_ID + ".cache", cacheFile
                                    )
                                ), app.getString(androidx.appcompat.R.string.abc_shareactionprovider_share_with)
                        )
                    )
                }

            }
        }

        binding.actionImportFile.setOnClickListener {
            startFilesForResult(importFile, "*/*")
        }
    }

    fun Parcelable.toBase64Str(): String {
        val parcel = Parcel.obtain()
        writeToParcel(parcel, 0)
        try {
            return Base64.encode(parcel.marshall())
        } finally {
            parcel.recycle()
        }
    }

    fun doBackup(profile: Boolean, rule: Boolean, setting: Boolean): String {
        val out = JsonObject()
        out.addProperty("version", 1)
        if (profile) {
            out.add("profiles", JsonArray().apply {
                SagerDatabase.proxyDao.getAll().forEach {
                    add(it.toBase64Str())
                }
            })

            out.add("groups", JsonArray().apply {
                SagerDatabase.groupDao.allGroups().forEach {
                    add(it.toBase64Str())
                }
            })
        }
        if (rule) {
            out.add("rules", JsonArray().apply {
                SagerDatabase.rulesDao.allRules().forEach {
                    add(it.toBase64Str())
                }
            })
            out.add("assets", JsonArray().apply {
                SagerDatabase.assetDao.getAll().forEach {
                    add(it.toBase64Str())
                }
            })
        }
        if (setting) {
            out.add("settings", JsonArray().apply {
                PublicDatabase.kvPairDao.all().forEach {
                    add(it.toBase64Str())
                }
            })
        }
        return GsonBuilder().setPrettyPrinting().create().toJson(out)
    }

    val importFile = registerForActivityResult(ActivityResultContracts.GetContent()) { file ->
        if (file != null) {
            runOnDefaultDispatcher {
                startImport(file)
            }
        }
    }

    suspend fun startImport(file: Uri) {
        val fileName = requireContext().contentResolver.query(file, null, null, null, null)
            ?.use { cursor ->
                cursor.moveToFirst()
                cursor.getColumnIndexOrThrow(OpenableColumns.DISPLAY_NAME).let(cursor::getString)
            }
            ?.takeIf { it.isNotBlank() } ?: file.pathSegments.last()
            .substringAfterLast('/')
            .substringAfter(':')

        if (!fileName.endsWith(".json")) {
            onMainDispatcher {
                snackbar(getString(R.string.backup_not_file, fileName)).show()
            }
            return
        }

        suspend fun invalid() = onMainDispatcher {
            onMainDispatcher {
                snackbar(getString(R.string.invalid_backup_file)).show()
            }
        }

        val content = try {
            parseJson((requireContext().contentResolver.openInputStream(file) ?: return).use {
                it.bufferedReader().readText()
            }).asJsonObject
        } catch (e: Exception) {
            Logs.w(e)
            invalid()
            return
        }
        val version = content.getInt("version")
        if (version == null || version != 1) {
            invalid()
            return
        }

        onMainDispatcher {
            val import = LayoutImportBinding.inflate(layoutInflater)
            if (!content.contains("profiles")) {
                import.backupConfigurations.isVisible = false
            }
            if (!content.contains("rules")) {
                import.backupRules.isVisible = false
            }
            if (!content.contains("settings")) {
                import.backupSettings.isVisible = false
            }
            MaterialAlertDialogBuilder(requireContext()).setTitle(R.string.backup_import)
                .setView(import.root)
                .setPositiveButton(R.string.backup_import) { _, _ ->
                    SagerNet.stopService()

                    val binding = LayoutProgressBinding.inflate(layoutInflater)
                    binding.content.text = getString(R.string.backup_importing)
                    val dialog = AlertDialog.Builder(requireContext())
                        .setView(binding.root)
                        .setCancelable(false)
                        .show()
                    runOnDefaultDispatcher {
                        runCatching {
                            finishImport(
                                content,
                                import.backupConfigurations.isChecked,
                                import.backupRules.isChecked,
                                import.backupSettings.isChecked
                            )
                            ProcessPhoenix.triggerRebirth(
                                requireContext(), Intent(requireContext(), MainActivity::class.java)
                            )
                        }.onFailure {
                            Logs.w(it)
                            onMainDispatcher {
                                alert(it.readableMessage).show()
                            }
                        }

                        onMainDispatcher {
                            dialog.dismiss()
                        }
                    }
                }
                .setNegativeButton(android.R.string.cancel, null)
                .show()
        }
    }

    fun finishImport(
        content: JsonObject, profile: Boolean, rule: Boolean, setting: Boolean
    ) {
        if (profile && content.contains("profiles")) {
            val profiles = mutableListOf<ProxyEntity>()
            content.getStringArray("profiles")?.forEach {
                val data = Base64.decode(it)
                val parcel = Parcel.obtain()
                parcel.unmarshall(data, 0, data.size)
                parcel.setDataPosition(0)
                profiles.add(ProxyEntity.CREATOR.createFromParcel(parcel))
                parcel.recycle()
            }
            SagerDatabase.proxyDao.reset()
            SagerDatabase.proxyDao.insert(profiles)

            val groups = mutableListOf<ProxyGroup>()
            content.getStringArray("groups")?.forEach {
                val data = Base64.decode(it)
                val parcel = Parcel.obtain()
                parcel.unmarshall(data, 0, data.size)
                parcel.setDataPosition(0)
                groups.add(ProxyGroup.CREATOR.createFromParcel(parcel))
                parcel.recycle()
            }
            SagerDatabase.groupDao.reset()
            SagerDatabase.groupDao.insert(groups)
        }
        if (rule && content.contains("rules")) {
            val rules = mutableListOf<RuleEntity>()
            content.getStringArray("rules")?.forEach {
                val data = Base64.decode(it)
                val parcel = Parcel.obtain()
                parcel.unmarshall(data, 0, data.size)
                parcel.setDataPosition(0)
                rules.add(ParcelizeBridge.createRule(parcel))
                parcel.recycle()
            }
            SagerDatabase.rulesDao.reset()
            SagerDatabase.rulesDao.insert(rules)

            val assets = mutableListOf<AssetEntity>()
            content.getStringArray("assets")?.forEach {
                val data = Base64.decode(it)
                val parcel = Parcel.obtain()
                parcel.unmarshall(data, 0, data.size)
                parcel.setDataPosition(0)
                assets.add(ParcelizeBridge.createAsset(parcel))
                parcel.recycle()
            }
            SagerDatabase.assetDao.reset()
            SagerDatabase.assetDao.insert(assets)
        }
        if (setting && content.contains("settings")) {
            val settings = mutableListOf<KeyValuePair>()
            content.getStringArray("settings")?.forEach {
                val data = Base64.decode(it)
                val parcel = Parcel.obtain()
                parcel.unmarshall(data, 0, data.size)
                parcel.setDataPosition(0)
                settings.add(KeyValuePair.CREATOR.createFromParcel(parcel))
                parcel.recycle()
            }
            PublicDatabase.kvPairDao.reset()
            PublicDatabase.kvPairDao.insert(settings)
        }
    }

}