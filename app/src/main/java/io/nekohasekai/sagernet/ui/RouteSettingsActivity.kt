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

import android.app.Activity
import android.content.DialogInterface
import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.os.Parcelable
import android.view.Menu
import android.view.MenuItem
import android.view.View
import android.view.WindowInsetsController.APPEARANCE_LIGHT_NAVIGATION_BARS
import androidx.activity.OnBackPressedCallback
import androidx.activity.result.component1
import androidx.activity.result.component2
import androidx.activity.result.contract.ActivityResultContracts
import androidx.annotation.LayoutRes
import androidx.appcompat.app.AlertDialog
import androidx.core.view.ViewCompat
import androidx.core.view.WindowCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.view.updatePadding
import androidx.preference.EditTextPreference
import androidx.preference.Preference
import androidx.preference.PreferenceDataStore
import androidx.preference.SwitchPreference
import com.github.shadowsocks.plugin.Empty
import com.github.shadowsocks.plugin.fragment.AlertDialogFragment
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.takisoft.preferencex.PreferenceFragmentCompat
import com.takisoft.preferencex.SimpleMenuPreference
import io.nekohasekai.sagernet.Key
import io.nekohasekai.sagernet.NetworkType
import io.nekohasekai.sagernet.R
import io.nekohasekai.sagernet.database.DataStore
import io.nekohasekai.sagernet.database.ProfileManager
import io.nekohasekai.sagernet.database.RuleEntity
import io.nekohasekai.sagernet.database.SagerDatabase
import io.nekohasekai.sagernet.database.preference.OnPreferenceDataStoreChangeListener
import io.nekohasekai.sagernet.ktx.FixedLinearLayoutManager
import io.nekohasekai.sagernet.ktx.Logs
import io.nekohasekai.sagernet.ktx.app
import io.nekohasekai.sagernet.ktx.onMainDispatcher
import io.nekohasekai.sagernet.ktx.runOnDefaultDispatcher
import io.nekohasekai.sagernet.utils.DirectBoot
import io.nekohasekai.sagernet.utils.PackageCache
import io.nekohasekai.sagernet.utils.Theme
import io.nekohasekai.sagernet.widget.AppListPreference
import kotlinx.parcelize.Parcelize

@Suppress("UNCHECKED_CAST")
class RouteSettingsActivity(
    @LayoutRes resId: Int = R.layout.layout_settings_activity,
) : ThemedActivity(resId),
    OnPreferenceDataStoreChangeListener {

    val callback = object : OnBackPressedCallback(enabled = false) {
        override fun handleOnBackPressed() {
            UnsavedChangesDialogFragment().apply {
                key()
            }.show(supportFragmentManager, null)
        }
    }

    fun init(packageName: String?) {
        RuleEntity().apply {
            if (!packageName.isNullOrEmpty()) {
                packages = listOf(packageName)
                name = app.getString(R.string.route_for, PackageCache.loadLabel(packageName))
            }
        }.init()
    }

    fun RuleEntity.init() {
        DataStore.routeName = name
        DataStore.routeDomain = domains
        DataStore.routeIP = ip
        DataStore.routePort = port
        DataStore.routeSourcePort = sourcePort
        DataStore.routeNetwork = network
        DataStore.routeSource = source
        DataStore.routeProtocol = protocol
        DataStore.routeAttrs = attrs
        DataStore.routeOutboundRule = outbound
        DataStore.routeOutbound = when (outbound) {
            0L -> 0
            -1L -> 1
            -2L -> 2
            else -> 3
        }
        DataStore.routeReverse = reverse
        DataStore.routeRedirect = redirect
        DataStore.routePackages = packages.joinToString("\n")
        DataStore.routeNetworkType = networkType
        DataStore.routeSSID = ssid
    }

    fun RuleEntity.serialize() {
        name = DataStore.routeName
        domains = DataStore.routeDomain
        ip = DataStore.routeIP
        port = DataStore.routePort
        sourcePort = DataStore.routeSourcePort
        network = DataStore.routeNetwork
        source = DataStore.routeSource
        protocol = DataStore.routeProtocol
        attrs = DataStore.routeAttrs
        outbound = when (DataStore.routeOutbound) {
            0 -> 0L
            1 -> -1L
            2 -> -2L
            else -> DataStore.routeOutboundRule
        }
        reverse = DataStore.routeReverse
        redirect = DataStore.routeRedirect
        packages = DataStore.routePackages.split("\n").filter { it.isNotEmpty() }
        networkType = DataStore.routeNetworkType
        ssid = DataStore.routeSSID

        if (DataStore.editingId == 0L) {
            enabled = true
        }
    }

    fun needSave(): Boolean {
        if (!DataStore.dirty) return false
        if (DataStore.routePackages.isEmpty() && DataStore.routeDomain.isEmpty() && DataStore.routeIP.isEmpty() && DataStore.routePort.isEmpty() && DataStore.routeSourcePort.isEmpty() && DataStore.routeNetwork.isEmpty() && DataStore.routeSource.isEmpty() && DataStore.routeProtocol.isEmpty() && DataStore.routeAttrs.isEmpty() && !(DataStore.routeReverse && DataStore.routeRedirect.isEmpty()) && DataStore.routeNetworkType.isEmpty()) {
            return false
        }
        return true
    }

    fun PreferenceFragmentCompat.createPreferences(
        savedInstanceState: Bundle?,
        rootKey: String?,
    ) {
        addPreferencesFromResource(R.xml.route_preferences)
    }

    val selectProfileForAdd = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { (resultCode, data) ->
        if (resultCode == Activity.RESULT_OK) runOnDefaultDispatcher {
            val profile = ProfileManager.getProfile(
                data!!.getLongExtra(
                    ProfileSelectActivity.EXTRA_PROFILE_ID, 0
                )
            ) ?: return@runOnDefaultDispatcher
            DataStore.routeOutboundRule = profile.id
            onMainDispatcher {
                outbound.value = "3"
                outbound.setSummary(profile.displayName())
            }
        }
    }

    val selectAppList = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { (_, _) ->
        apps.postUpdate()
    }

    lateinit var outbound: SimpleMenuPreference
    lateinit var reverse: SwitchPreference
    lateinit var redirect: EditTextPreference
    lateinit var apps: AppListPreference
    lateinit var networkType: SimpleMenuPreference
    lateinit var ssid: EditTextPreference

    fun PreferenceFragmentCompat.viewCreated(view: View, savedInstanceState: Bundle?) {
        outbound = findPreference(Key.ROUTE_OUTBOUND)!!
        reverse = findPreference(Key.ROUTE_REVERSE)!!
        redirect = findPreference(Key.ROUTE_REDIRECT)!!
        apps = findPreference(Key.ROUTE_PACKAGES)!!
        networkType = findPreference(Key.ROUTE_NETWORK_TYPE)!!
        ssid = findPreference(Key.ROUTE_SSID)!!

        fun updateReverse(enabled: Boolean = outbound.value == "3") {
            reverse.isVisible = enabled
            redirect.isVisible = enabled
            redirect.isEnabled = reverse.isChecked
        }

        updateReverse()

        reverse.setOnPreferenceChangeListener { _, newValue ->
            redirect.isEnabled = newValue as Boolean
            true
        }

        val outboundEntries = resources.getStringArray(R.array.outbound_entry)
        if (DataStore.routeOutbound == 3) {
            outbound.setSummary(ProfileManager.getProfile(DataStore.routeOutboundRule)?.displayName())
        } else {
            outbound.setSummary(outboundEntries[DataStore.routeOutbound.toString().toInt()])
        }
        outbound.apply {
            setEntries(R.array.outbound_entry)
            setEntryValues(R.array.outbound_value)
            setOnPreferenceChangeListener { _, newValue ->
                if (newValue.toString() == "3") {
                    updateReverse(true)
                    selectProfileForAdd.launch(
                        Intent(this@RouteSettingsActivity, ProfileSelectActivity::class.java)
                    )
                    false
                } else {
                    updateReverse(false)
                    setSummary(outboundEntries[newValue.toString().toInt()])
                    true
                }
            }
        }

        apps.setOnPreferenceClickListener {
            selectAppList.launch(
                Intent(
                    this@RouteSettingsActivity, AppListActivity::class.java
                )
            )
            true
        }

        fun updateNetwork(newValue: String = networkType.value) {
            ssid.isVisible = newValue == NetworkType.WIFI
        }

        updateNetwork()

        networkType.setOnPreferenceChangeListener { _, newValue ->
            updateNetwork(newValue as String)
            true
        }
    }

    fun PreferenceFragmentCompat.displayPreferenceDialog(preference: Preference): Boolean {
        return false
    }

    class UnsavedChangesDialogFragment : AlertDialogFragment<Empty, Empty>() {
        override fun AlertDialog.Builder.prepare(listener: DialogInterface.OnClickListener) {
            setTitle(R.string.unsaved_changes_prompt)
            setPositiveButton(android.R.string.ok) { _, _ ->
                runOnDefaultDispatcher {
                    (requireActivity() as RouteSettingsActivity).saveAndExit()
                }
            }
            setNegativeButton(android.R.string.cancel) { _, _ ->
                requireActivity().finish()
            }
        }
    }

    @Parcelize
    data class ProfileIdArg(val ruleId: Long) : Parcelable
    class DeleteConfirmationDialogFragment : AlertDialogFragment<ProfileIdArg, Empty>() {
        override fun AlertDialog.Builder.prepare(listener: DialogInterface.OnClickListener) {
            setTitle(R.string.delete_route_prompt)
            setPositiveButton(android.R.string.ok) { _, _ ->
                runOnDefaultDispatcher {
                    ProfileManager.deleteRule(arg.ruleId)
                }
                requireActivity().finish()
            }
            setNegativeButton(android.R.string.cancel, null)
        }
    }

    companion object {
        const val EXTRA_ROUTE_ID = "id"
        const val EXTRA_PACKAGE_NAME = "pkg"
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

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
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            when (Theme.usingNightMode()) {
                true -> {
                    window.insetsController?.setSystemBarsAppearance(
                        0, APPEARANCE_LIGHT_NAVIGATION_BARS
                    )
                }
                else -> {
                    window.insetsController?.setSystemBarsAppearance(
                        APPEARANCE_LIGHT_NAVIGATION_BARS, APPEARANCE_LIGHT_NAVIGATION_BARS
                    )
                }
            }
        }

        setSupportActionBar(findViewById(R.id.toolbar))
        supportActionBar?.apply {
            setTitle(R.string.cag_route)
            setDisplayHomeAsUpEnabled(true)
            setHomeAsUpIndicator(R.drawable.ic_navigation_close)
        }

        if (savedInstanceState == null) {
            val editingId = intent.getLongExtra(EXTRA_ROUTE_ID, 0L)
            DataStore.editingId = editingId
            runOnDefaultDispatcher {
                if (editingId == 0L) {
                    init(intent.getStringExtra(EXTRA_PACKAGE_NAME))
                } else {
                    val ruleEntity = SagerDatabase.rulesDao.getById(editingId)
                    if (ruleEntity == null) {
                        onMainDispatcher {
                            finish()
                        }
                        return@runOnDefaultDispatcher
                    }
                    ruleEntity.init()
                }

                onMainDispatcher {
                    supportFragmentManager.beginTransaction()
                        .replace(R.id.settings, MyPreferenceFragmentCompat().apply {
                            activity = this@RouteSettingsActivity
                        })
                        .commit()

                    DataStore.dirty = false
                    DataStore.profileCacheStore.registerChangeListener(this@RouteSettingsActivity)
                }
            }


        }

        onBackPressedDispatcher.addCallback(this, callback)
    }

    suspend fun saveAndExit() {

        if (!needSave()) {
            onMainDispatcher {
                MaterialAlertDialogBuilder(this@RouteSettingsActivity).setTitle(R.string.empty_route)
                    .setMessage(R.string.empty_route_notice)
                    .setPositiveButton(android.R.string.ok, null)
                    .show()
            }
            return
        }

        val editingId = DataStore.editingId
        if (editingId == 0L) {
            if (intent.hasExtra(EXTRA_PACKAGE_NAME)) {
                setResult(RESULT_OK, Intent())
            }

            ProfileManager.createRule(RuleEntity().apply { serialize() })
        } else {
            val entity = SagerDatabase.rulesDao.getById(DataStore.editingId)
            if (entity == null) {
                finish()
                return
            }
            ProfileManager.updateRule(entity.apply { serialize() })
        }
        if (editingId == DataStore.selectedProxy && DataStore.directBootAware) DirectBoot.update()
        finish()

    }

    override fun onCreateOptionsMenu(menu: Menu): Boolean {
        menuInflater.inflate(R.menu.profile_config_menu, menu)
        return true
    }

    override fun onOptionsItemSelected(item: MenuItem) = when (item.itemId) {
        R.id.action_delete -> {
            if (DataStore.editingId == 0L) {
                finish()
            } else {
                DeleteConfirmationDialogFragment().apply {
                    arg(ProfileIdArg(DataStore.editingId))
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

        var activity: RouteSettingsActivity? = null

        override fun onCreatePreferencesFix(savedInstanceState: Bundle?, rootKey: String?) {
            preferenceManager.preferenceDataStore = DataStore.profileCacheStore
            try {
                activity = (requireActivity() as RouteSettingsActivity).apply {
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
                WindowInsetsCompat.CONSUMED
            }
            activity?.apply {
                viewCreated(view, savedInstanceState)
            }
        }

        override fun onDisplayPreferenceDialog(preference: Preference) {
            activity?.apply {
                if (displayPreferenceDialog(preference)) return
            }
            super.onDisplayPreferenceDialog(preference)
        }

    }

    object PasswordSummaryProvider : Preference.SummaryProvider<EditTextPreference> {

        override fun provideSummary(preference: EditTextPreference): CharSequence {
            val text = preference.text
            return if (text.isNullOrEmpty()) {
                preference.context.getString(androidx.preference.R.string.not_set)
            } else {
                "\u2022".repeat(text.length)
            }
        }

    }

}