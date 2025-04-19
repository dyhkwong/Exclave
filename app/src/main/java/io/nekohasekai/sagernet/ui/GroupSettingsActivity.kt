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
import androidx.preference.*
import cn.hutool.core.util.NumberUtil
import com.github.shadowsocks.plugin.Empty
import com.github.shadowsocks.plugin.fragment.AlertDialogFragment
import com.takisoft.preferencex.PreferenceFragmentCompat
import com.takisoft.preferencex.SimpleMenuPreference
import io.nekohasekai.sagernet.GroupType
import io.nekohasekai.sagernet.Key
import io.nekohasekai.sagernet.R
import io.nekohasekai.sagernet.SubscriptionType
import io.nekohasekai.sagernet.database.*
import io.nekohasekai.sagernet.database.preference.OnPreferenceDataStoreChangeListener
import io.nekohasekai.sagernet.ktx.FixedLinearLayoutManager
import io.nekohasekai.sagernet.ktx.Logs
import io.nekohasekai.sagernet.ktx.applyDefaultValues
import io.nekohasekai.sagernet.ktx.onMainDispatcher
import io.nekohasekai.sagernet.ktx.runOnDefaultDispatcher
import io.nekohasekai.sagernet.utils.DirectBoot
import io.nekohasekai.sagernet.widget.UserAgentPreference
import kotlinx.parcelize.Parcelize

@Suppress("UNCHECKED_CAST")
class GroupSettingsActivity(
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

    private lateinit var frontProxyPreference: SimpleMenuPreference
    private lateinit var landingProxyPreference: SimpleMenuPreference

    fun ProxyGroup.init() {
        DataStore.groupName = name ?: ""
        DataStore.groupType = type
        DataStore.groupOrder = order
        val subscription = subscription ?: SubscriptionBean().applyDefaultValues()
        DataStore.subscriptionType = subscription.type
        DataStore.subscriptionLink = subscription.link
        DataStore.subscriptionToken = subscription.token
        DataStore.subscriptionDeduplication = subscription.deduplication
        DataStore.subscriptionUpdateWhenConnectedOnly = subscription.updateWhenConnectedOnly
        DataStore.subscriptionUserAgent = subscription.customUserAgent
        DataStore.subscriptionAutoUpdate = subscription.autoUpdate
        DataStore.subscriptionAutoUpdateDelay = subscription.autoUpdateDelay
        DataStore.subscriptionNameFilter = subscription.nameFilter
        DataStore.frontProxyOutbound = frontProxy
        DataStore.landingProxyOutbound = landingProxy
        DataStore.frontProxy = if (frontProxy >= 0) 1 else 0
        DataStore.landingProxy = if (landingProxy >= 0) 1 else 0
    }

    fun ProxyGroup.serialize() {
        type = DataStore.groupType
        name = DataStore.groupName.takeIf { it.isNotEmpty() } ?:
                if (type == GroupType.SUBSCRIPTION) {
                    getString(R.string.subscription)
                } else {
                    getString(R.string.menu_group)
                }
        order = DataStore.groupOrder

        frontProxy = if (DataStore.frontProxy == 1) DataStore.frontProxyOutbound else -1
        landingProxy = if (DataStore.landingProxy == 1) DataStore.landingProxyOutbound else -1

        val isSubscription = type == GroupType.SUBSCRIPTION
        if (isSubscription) {
            subscription = (subscription ?: SubscriptionBean().applyDefaultValues()).apply {
                type = DataStore.subscriptionType
                link = DataStore.subscriptionLink
                token = DataStore.subscriptionToken
                deduplication = DataStore.subscriptionDeduplication
                updateWhenConnectedOnly = DataStore.subscriptionUpdateWhenConnectedOnly
                customUserAgent = DataStore.subscriptionUserAgent
                autoUpdate = DataStore.subscriptionAutoUpdate
                autoUpdateDelay = DataStore.subscriptionAutoUpdateDelay
                nameFilter = DataStore.subscriptionNameFilter
            }
        }
    }

    fun needSave(): Boolean {
        if (!DataStore.dirty) {
            return false
        }
        return true
    }

    fun PreferenceFragmentCompat.createPreferences(
        savedInstanceState: Bundle?,
        rootKey: String?,
    ) {
        addPreferencesFromResource(R.xml.group_preferences)

        frontProxyPreference = findPreference(Key.GROUP_FRONT_PROXY)!!
        if (DataStore.frontProxy == 1) {
            frontProxyPreference.setSummary(ProfileManager.getProfile(DataStore.frontProxyOutbound)?.displayName())
        } else {
            frontProxyPreference.setSummary(resources.getString(R.string.disable))
        }
        frontProxyPreference.apply {
            setEntries(R.array.front_landing_proxy_entry)
            setEntryValues(R.array.front_landing_proxy_value)
            setOnPreferenceChangeListener { _, newValue ->
                if (newValue.toString() == "1") {
                    selectProfileForAddFront.launch(
                        Intent(this@GroupSettingsActivity, ProfileSelectActivity::class.java)
                    )
                    false
                } else {
                    setSummary(resources.getString(R.string.disable))
                    true
                }
            }
        }
        landingProxyPreference = findPreference(Key.GROUP_LANDING_PROXY)!!
        if (DataStore.landingProxy == 1) {
            landingProxyPreference.setSummary(ProfileManager.getProfile(DataStore.landingProxyOutbound)?.displayName())
        } else {
            landingProxyPreference.setSummary(resources.getString(R.string.disable))
        }
        landingProxyPreference.apply {
            setEntries(R.array.front_landing_proxy_entry)
            setEntryValues(R.array.front_landing_proxy_value)
            setOnPreferenceChangeListener { _, newValue ->
                if (newValue.toString() == "1") {
                    selectProfileForAddLanding.launch(
                        Intent(this@GroupSettingsActivity, ProfileSelectActivity::class.java)
                    )
                    false
                } else {
                    setSummary(resources.getString(R.string.disable))
                    true
                }
            }
        }

        val groupType = findPreference<SimpleMenuPreference>(Key.GROUP_TYPE)!!
        val groupSubscription = findPreference<PreferenceCategory>(Key.GROUP_SUBSCRIPTION)!!
        val subscriptionUpdate = findPreference<PreferenceCategory>(Key.SUBSCRIPTION_UPDATE)!!

        fun updateGroupType(groupType: Int = DataStore.groupType) {
            val isSubscription = groupType == GroupType.SUBSCRIPTION
            groupSubscription.isVisible = isSubscription
            subscriptionUpdate.isVisible = isSubscription
        }
        updateGroupType()
        groupType.setOnPreferenceChangeListener { _, newValue ->
            updateGroupType((newValue as String).toInt())
            true
        }

        val subscriptionType = findPreference<SimpleMenuPreference>(Key.SUBSCRIPTION_TYPE)!!
        val subscriptionLink = findPreference<EditTextPreference>(Key.SUBSCRIPTION_LINK)!!
        val subscriptionToken = findPreference<EditTextPreference>(Key.SUBSCRIPTION_TOKEN)!!
        val subscriptionUserAgent = findPreference<UserAgentPreference>(Key.SUBSCRIPTION_USER_AGENT)!!

        fun updateSubscriptionType(subscriptionType: Int = DataStore.subscriptionType) {
            subscriptionLink.isVisible = subscriptionType != SubscriptionType.OOCv1
            subscriptionToken.isVisible = subscriptionType == SubscriptionType.OOCv1
            subscriptionUserAgent.notifyChanged()
        }
        updateSubscriptionType()
        subscriptionType.setOnPreferenceChangeListener { _, newValue ->
            updateSubscriptionType((newValue as String).toInt())
            true
        }

        val subscriptionAutoUpdate = findPreference<SwitchPreference>(Key.SUBSCRIPTION_AUTO_UPDATE)!!
        val subscriptionAutoUpdateDelay = findPreference<EditTextPreference>(Key.SUBSCRIPTION_AUTO_UPDATE_DELAY)!!
        subscriptionAutoUpdateDelay.isEnabled = subscriptionAutoUpdate.isChecked
        subscriptionAutoUpdateDelay.setOnPreferenceChangeListener { _, newValue ->
            NumberUtil.isInteger(newValue as String) && newValue.toInt() >= 15
        }
        subscriptionAutoUpdate.setOnPreferenceChangeListener { _, newValue ->
            subscriptionAutoUpdateDelay.isEnabled = (newValue as Boolean)
            true
        }
    }

    class UnsavedChangesDialogFragment : AlertDialogFragment<Empty, Empty>() {
        override fun AlertDialog.Builder.prepare(listener: DialogInterface.OnClickListener) {
            setTitle(R.string.unsaved_changes_prompt)
            setPositiveButton(android.R.string.ok) { _, _ ->
                runOnDefaultDispatcher {
                    (requireActivity() as GroupSettingsActivity).saveAndExit()
                }
            }
            setNegativeButton(android.R.string.cancel) { _, _ ->
                requireActivity().finish()
            }
        }
    }

    @Parcelize
    data class GroupIdArg(val groupId: Long) : Parcelable
    class DeleteConfirmationDialogFragment : AlertDialogFragment<GroupIdArg, Empty>() {
        override fun AlertDialog.Builder.prepare(listener: DialogInterface.OnClickListener) {
            setTitle(R.string.delete_group_prompt)
            setPositiveButton(android.R.string.ok) { _, _ ->
                runOnDefaultDispatcher {
                    GroupManager.deleteGroup(arg.groupId)
                }
                requireActivity().finish()
            }
            setNegativeButton(android.R.string.cancel, null)
        }
    }

    companion object {
        const val EXTRA_GROUP_ID = "id"
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

        setSupportActionBar(findViewById(R.id.toolbar))
        supportActionBar?.apply {
            setTitle(R.string.group_settings)
            setDisplayHomeAsUpEnabled(true)
            setHomeAsUpIndicator(R.drawable.ic_navigation_close)
        }

        if (savedInstanceState == null) {
            val editingId = intent.getLongExtra(EXTRA_GROUP_ID, 0L)
            DataStore.editingId = editingId
            runOnDefaultDispatcher {
                if (editingId == 0L) {
                    ProxyGroup().init()
                } else {
                    val entity = SagerDatabase.groupDao.getById(editingId)
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
                            activity = this@GroupSettingsActivity
                        })
                        .commit()

                    DataStore.dirty = false
                    DataStore.profileCacheStore.registerChangeListener(this@GroupSettingsActivity)
                }
            }

            onBackPressedDispatcher.addCallback(this, callback)
        }

    }

    suspend fun saveAndExit() {

        val editingId = DataStore.editingId
        if (editingId == 0L) {
            GroupManager.createGroup(ProxyGroup().apply { serialize() })
        } else if (needSave()) {
            val entity = SagerDatabase.groupDao.getById(DataStore.editingId)
            if (entity == null) {
                finish()
                return
            }
            GroupManager.updateGroup(entity.apply { serialize() })
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
                    arg(GroupIdArg(DataStore.editingId))
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

        var activity: GroupSettingsActivity? = null

        override fun onCreatePreferencesFix(savedInstanceState: Bundle?, rootKey: String?) {
            preferenceManager.preferenceDataStore = DataStore.profileCacheStore
            try {
                activity = (requireActivity() as GroupSettingsActivity).apply {
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

    val selectProfileForAddFront = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { (resultCode, data) ->
        if (resultCode == Activity.RESULT_OK) runOnDefaultDispatcher {
            val profile = ProfileManager.getProfile(
                data!!.getLongExtra(ProfileSelectActivity.EXTRA_PROFILE_ID, 0)
            ) ?: return@runOnDefaultDispatcher
            DataStore.frontProxyOutbound = profile.id
            onMainDispatcher {
                frontProxyPreference.value = "1"
                frontProxyPreference.setSummary(profile.displayName())
            }
        }
    }

    val selectProfileForAddLanding = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { (resultCode, data) ->
        if (resultCode == Activity.RESULT_OK) runOnDefaultDispatcher {
            val profile = ProfileManager.getProfile(
                data!!.getLongExtra(ProfileSelectActivity.EXTRA_PROFILE_ID, 0)
            ) ?: return@runOnDefaultDispatcher
            DataStore.landingProxyOutbound = profile.id
            onMainDispatcher {
                landingProxyPreference.value = "1"
                landingProxyPreference.setSummary(profile.displayName())
            }
        }
    }

}