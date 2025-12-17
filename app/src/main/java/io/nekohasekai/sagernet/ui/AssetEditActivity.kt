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

package io.nekohasekai.sagernet.ui

import android.os.Bundle
import android.view.Menu
import android.view.MenuItem
import android.view.View
import androidx.activity.OnBackPressedCallback
import androidx.annotation.LayoutRes
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.view.updatePadding
import androidx.preference.PreferenceDataStore
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.takisoft.preferencex.PreferenceFragmentCompat
import io.nekohasekai.sagernet.Key
import io.nekohasekai.sagernet.R
import io.nekohasekai.sagernet.database.AssetEntity
import io.nekohasekai.sagernet.database.DataStore
import io.nekohasekai.sagernet.database.SagerDatabase
import io.nekohasekai.sagernet.database.preference.OnPreferenceDataStoreChangeListener
import io.nekohasekai.sagernet.ktx.Logs
import io.nekohasekai.sagernet.ktx.app
import io.nekohasekai.sagernet.ktx.isHTTPorHTTPSURL
import io.nekohasekai.sagernet.ktx.listByLine
import io.nekohasekai.sagernet.ktx.onMainDispatcher
import io.nekohasekai.sagernet.ktx.runOnDefaultDispatcher
import java.io.File

class AssetEditActivity(
    @LayoutRes resId: Int = R.layout.layout_config_settings,
) : ThemedActivity(resId),
    OnPreferenceDataStoreChangeListener {

    var dirty = false

    override val onBackPressedCallback = object : OnBackPressedCallback(enabled = false) {
        override fun handleOnBackPressed() {
            MaterialAlertDialogBuilder(this@AssetEditActivity)
                .setTitle(R.string.unsaved_changes_prompt)
                .setPositiveButton(android.R.string.ok) { _, _ ->
                    runOnDefaultDispatcher {
                        saveAndExit()
                    }
                }
                .setNegativeButton(android.R.string.cancel) { _, _ ->
                    finish()
                }
                .show()
        }
    }

    fun AssetEntity.init() {
        DataStore.assetName = name
        DataStore.assetUrl = url
    }

    fun AssetEntity.serialize() {
        name = DataStore.assetName
        url = DataStore.assetUrl
    }

    fun needSave(): Boolean {
        return dirty
    }

    fun validate() {
        val filename = DataStore.assetName
        if (filename.length > 255) {
            error(getString(R.string.route_asset_invalid_filename, filename))
        }
        // https://cs.android.com/android/platform/superproject/+/master:frameworks/base/core/java/android/os/FileUtils.java;drc=71e11ae9ba8e1f5716b7d1a5c77c1fea9a9442b7;l=997
        // These characters will cause issues on older Android
        if (filename.contains('"') || filename.contains('*')
            || filename.contains('/') || filename.contains(':')
            || filename.contains('<') || filename.contains('>')
            || filename.contains('?') || filename.contains('\\')
            || filename.contains('|') || filename.contains('\u007f')) {
            error(getString(R.string.route_asset_invalid_filename, filename))
        }
        if (filename.any { it in '\u0000'..'\u001f' }) {
            error(getString(R.string.route_asset_invalid_filename, filename))
        }
        if (File(app.externalAssets, filename).canonicalPath.substringAfterLast('/') != DataStore.assetName) {
            error(getString(R.string.route_asset_invalid_filename, filename))
        }
        if (!filename.endsWith(".dat")) {
            error(getString(R.string.route_not_asset, filename))
        }
        if (filename == "geosite.dat" || filename == "geoip.dat") {
            error(getString(R.string.route_asset_reserved_filename,  filename))
        }
        if (filename != DataStore.editingAssetName && SagerDatabase.assetDao.get(filename) != null) {
            error(getString(R.string.route_asset_duplicate_filename,  filename))
        }
        if (DataStore.assetUrl.listByLine().size > 1 || !isHTTPorHTTPSURL(DataStore.assetUrl)) {
            error(getString(R.string.route_asset_invalid_url,  DataStore.assetUrl))
        }
    }

    fun PreferenceFragmentCompat.createPreferences(
        savedInstanceState: Bundle?,
        rootKey: String?,
    ) {
        addPreferencesFromResource(R.xml.asset_preferences)
    }

    companion object {
        const val EXTRA_ASSET_NAME = "name"
        const val KEY_DIRTY = "dirty"
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        setSupportActionBar(findViewById(R.id.toolbar))
        supportActionBar?.apply {
            setTitle(R.string.route_asset_settings)
            setDisplayHomeAsUpEnabled(true)
            setHomeAsUpIndicator(R.drawable.ic_navigation_close)
        }

        if (savedInstanceState == null) {
            val editingAssetName = intent.getStringExtra(EXTRA_ASSET_NAME) ?: ""
            DataStore.editingAssetName = editingAssetName
            runOnDefaultDispatcher {
                if (editingAssetName.isEmpty()) {
                    AssetEntity().init()
                } else {
                    val entity = SagerDatabase.assetDao.get(editingAssetName)
                    if (entity == null) {
                        onMainDispatcher {
                            finish()
                        }
                        return@runOnDefaultDispatcher
                    }
                    entity.init()
                }

                onMainDispatcher {
                    supportFragmentManager.beginTransaction()
                        .replace(R.id.settings, MyPreferenceFragmentCompat())
                        .commit()

                    DataStore.profileCacheStore.registerChangeListener(this@AssetEditActivity)
                }
            }

        }

        savedInstanceState?.getBoolean(KEY_DIRTY)?.let {
            dirty = it
            onBackPressedCallback.isEnabled = it
        }
    }

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        outState.putBoolean(KEY_DIRTY, dirty)
    }

    suspend fun saveAndExit() {

        try {
            validate()
        } catch (e: Exception) {
            onMainDispatcher {
                MaterialAlertDialogBuilder(this@AssetEditActivity).setTitle(R.string.error_title)
                    .setMessage(e.localizedMessage)
                    .setPositiveButton(android.R.string.ok, null)
                    .show()
            }
            return
        }
        val editingAssetName = DataStore.editingAssetName
        if (editingAssetName.isEmpty()) {
            SagerDatabase.assetDao.create(AssetEntity().apply { serialize() })
        } else if (needSave()) {
            val entity = SagerDatabase.assetDao.get(DataStore.editingAssetName)
            if (entity == null) {
                finish()
                return
            }
            SagerDatabase.assetDao.update(entity.apply { serialize() })
        }

        finish()

    }

    override fun onCreateOptionsMenu(menu: Menu): Boolean {
        menuInflater.inflate(R.menu.profile_config_menu, menu)
        return true
    }

    override fun onOptionsItemSelected(item: MenuItem) = when (item.itemId) {
        R.id.action_delete -> {
            if (DataStore.editingAssetName == "") {
                finish()
            } else {
                MaterialAlertDialogBuilder(this)
                    .setTitle(R.string.route_asset_delete_prompt)
                    .setPositiveButton(android.R.string.ok) { _, _ ->
                        runOnDefaultDispatcher {
                            File(app.externalAssets, DataStore.editingAssetName).deleteRecursively()
                            SagerDatabase.assetDao.delete(DataStore.editingAssetName)
                        }
                        finish()
                    }
                    .setNegativeButton(android.R.string.cancel, null)
                    .show()
            }
            true
        }
        R.id.action_apply -> {
            runOnDefaultDispatcher {
                saveAndExit()
            }
            true
        }
        else -> false
    }

    override fun onSupportNavigateUp(): Boolean {
        if (!super.onSupportNavigateUp()) finish()
        return true
    }

    override fun onDestroy() {
        DataStore.profileCacheStore.unregisterChangeListener(this)
        super.onDestroy()
    }

    override fun onPreferenceDataStoreChanged(store: PreferenceDataStore, key: String) {
        if (key != Key.PROFILE_DIRTY) {
            dirty = true
            onBackPressedCallback.isEnabled = true
        }
    }

    class MyPreferenceFragmentCompat : PreferenceFragmentCompat() {

        val activity: AssetEditActivity
            get() = requireActivity() as AssetEditActivity

        override fun onCreatePreferencesFix(savedInstanceState: Bundle?, rootKey: String?) {
            preferenceManager.preferenceDataStore = DataStore.profileCacheStore
            try {
                activity.apply {
                    createPreferences(savedInstanceState, rootKey)
                }
            } catch (e: Exception) {
                Logs.w(e)
            }
        }

        override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
            super.onViewCreated(view, savedInstanceState)

            ViewCompat.setOnApplyWindowInsetsListener(listView) { v, insets ->
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
        }
    }

}