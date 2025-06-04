package io.nekohasekai.sagernet.ui

import android.content.DialogInterface
import android.os.Bundle
import android.os.Parcelable
import android.view.Menu
import android.view.MenuItem
import android.view.View
import androidx.activity.OnBackPressedCallback
import androidx.annotation.LayoutRes
import androidx.appcompat.app.AlertDialog
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.view.updatePadding
import androidx.preference.PreferenceDataStore
import cn.hutool.core.lang.Validator.isUrl
import com.github.shadowsocks.plugin.Empty
import com.github.shadowsocks.plugin.fragment.AlertDialogFragment
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
import io.nekohasekai.sagernet.ktx.onMainDispatcher
import io.nekohasekai.sagernet.ktx.runOnDefaultDispatcher
import kotlinx.parcelize.Parcelize
import java.io.File

class AssetEditActivity(
    @LayoutRes resId: Int = R.layout.layout_config_settings,
) : ThemedActivity(resId),
    OnPreferenceDataStoreChangeListener {

    val callback = object : OnBackPressedCallback(enabled = false) {
        override fun handleOnBackPressed() {
            UnsavedChangesDialogFragment().apply {
                key()
            }.show(supportFragmentManager, null)
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
        if (!DataStore.dirty) return false
        return true
    }

    fun validate() {
        if (DataStore.assetName.length > 255 || DataStore.assetName.contains('/')) {
            error(getString(R.string.route_asset_invalid_filename, DataStore.assetName))
        }
        if (File(app.externalAssets, DataStore.assetName).canonicalPath.substringAfterLast('/') != DataStore.assetName) {
            error(getString(R.string.route_asset_invalid_filename, DataStore.assetName))
        }
        if (!DataStore.assetName.endsWith(".dat")) {
            error(getString(R.string.route_not_asset, DataStore.assetName))
        }
        if (DataStore.assetName == "geosite.dat" || DataStore.assetName == "geoip.dat") {
            error(getString(R.string.route_asset_reserved_filename,  DataStore.assetName))
        }
        if (DataStore.assetName != DataStore.editingAssetName && SagerDatabase.assetDao.get(DataStore.assetName) != null) {
            error(getString(R.string.route_asset_duplicate_filename,  DataStore.assetName))
        }
        if (!isUrl(DataStore.assetUrl)) {
            error(getString(R.string.route_asset_invalid_url,  DataStore.assetUrl))
        }
    }

    fun PreferenceFragmentCompat.createPreferences(
        savedInstanceState: Bundle?,
        rootKey: String?,
    ) {
        addPreferencesFromResource(R.xml.asset_preferences)
    }

    class UnsavedChangesDialogFragment : AlertDialogFragment<Empty, Empty>() {
        override fun AlertDialog.Builder.prepare(listener: DialogInterface.OnClickListener) {
            setTitle(R.string.unsaved_changes_prompt)
            setPositiveButton(android.R.string.ok) { _, _ ->
                runOnDefaultDispatcher {
                    (requireActivity() as AssetEditActivity).saveAndExit()
                }
            }
            setNegativeButton(android.R.string.cancel) { _, _ ->
                requireActivity().finish()
            }
        }
    }

    @Parcelize
    data class AssetNameArg(val assetName: String) : Parcelable
    class DeleteConfirmationDialogFragment : AlertDialogFragment<AssetNameArg, Empty>() {
        override fun AlertDialog.Builder.prepare(listener: DialogInterface.OnClickListener) {
            setTitle(R.string.route_asset_delete_prompt)
            setPositiveButton(android.R.string.ok) { _, _ ->
                runOnDefaultDispatcher {
                    File(app.externalAssets, arg.assetName).deleteRecursively()
                    SagerDatabase.assetDao.delete(arg.assetName)
                }
                requireActivity().finish()
            }
            setNegativeButton(android.R.string.cancel, null)
        }
    }

    companion object {
        const val EXTRA_ASSET_NAME = "name"
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

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
                        .replace(R.id.settings, MyPreferenceFragmentCompat().apply {
                            activity = this@AssetEditActivity
                        })
                        .commit()

                    DataStore.dirty = false
                    DataStore.profileCacheStore.registerChangeListener(this@AssetEditActivity)
                }
            }

        }

        onBackPressedDispatcher.addCallback(this, callback)
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
                DeleteConfirmationDialogFragment().apply {
                    arg(AssetNameArg(DataStore.editingAssetName))
                    key()
                }.show(supportFragmentManager, null)
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
            DataStore.dirty = true
            callback.isEnabled = true
        }
    }

    class MyPreferenceFragmentCompat : PreferenceFragmentCompat() {

        var activity: AssetEditActivity? = null

        override fun onCreatePreferencesFix(savedInstanceState: Bundle?, rootKey: String?) {
            preferenceManager.preferenceDataStore = DataStore.profileCacheStore
            try {
                activity = (requireActivity() as AssetEditActivity).apply {
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