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

package io.nekohasekai.sagernet.group

import com.github.shadowsocks.plugin.PluginOptions
import com.google.gson.JsonObject
import io.nekohasekai.sagernet.ExtraType
import io.nekohasekai.sagernet.R
import io.nekohasekai.sagernet.SagerNet
import io.nekohasekai.sagernet.database.*
import io.nekohasekai.sagernet.fmt.AbstractBean
import io.nekohasekai.sagernet.fmt.shadowsocks.ShadowsocksBean
import io.nekohasekai.sagernet.ktx.*
import libcore.Libcore
import libcore.URL

object OpenOnlineConfigUpdater : GroupUpdater() {

    override suspend fun doUpdate(
        proxyGroup: ProxyGroup,
        subscription: SubscriptionBean,
        userInterface: GroupManager.Interface?,
        byUser: Boolean
    ) {
        val apiToken: JsonObject
        val baseLink: URL
        val certSha256: String?
        try {
            apiToken = parseJson(subscription.token).asJsonObject

            val version = apiToken.getInt("version")
            if (version != 1) {
                if (version != null) {
                    error("Unsupported OOC version $version")
                } else {
                    error("Missing field: version")
                }
            }
            val baseUrl = apiToken.getString("baseUrl")
            when {
                baseUrl.isNullOrEmpty() -> {
                    error("Missing field: baseUrl")
                }
                baseUrl.endsWith("/") -> {
                    error("baseUrl must not contain a trailing slash")
                }
                !baseUrl.startsWith("https://", ignoreCase = true) -> {
                    error("Protocol scheme must be https")
                }
                else -> baseLink = Libcore.parseURL(baseUrl)
            }
            val secret = apiToken.getString("secret")
            if (secret.isNullOrEmpty()) error("Missing field: secret")
            baseLink.addPathSegments(secret, "ooc/v1")

            val userId = apiToken.getString("userId")
            if (userId.isNullOrEmpty()) error("Missing field: userId")
            baseLink.addPathSegments(userId)
            certSha256 = apiToken.getString("certSha256")
            if (!certSha256.isNullOrEmpty()) {
                when {
                    certSha256.length != 64 -> {
                        error("certSha256 must be a SHA-256 hexadecimal string")
                    }
                    !certSha256.all {
                        (it in '0'..'9') || (it in 'a'..'f')

                    } -> {
                        error("certSha256 must be a hexadecimal string with lowercase letters")
                    }
                }
            }
        } catch (_: Exception) {
            error(app.getString(R.string.ooc_subscription_token_invalid))
        }

        val response = Libcore.newHttpClient().apply {
            restrictedTLS()
            if (certSha256 != null) pinnedSHA256(certSha256)
            if (SagerNet.started && DataStore.startedProfile > 0) {
                useSocks5(DataStore.socksPort)
            }
        }.newRequest().apply {
            setURL(baseLink.string)
            setUserAgent(subscription.customUserAgent.takeIf { it.isNotEmpty() }
                ?: USER_AGENT)
        }.execute()

        val oocResponse = try {
            parseJson(response.contentString).asJsonObject
        } catch(_: Exception) {
            error("invalid response")
        }
        subscription.username = oocResponse.getString("username") ?: ""
        subscription.bytesUsed = oocResponse.getLong("bytesUsed") ?: -1
        subscription.bytesRemaining = oocResponse.getLong("bytesRemaining") ?: -1
        subscription.expiryDate = oocResponse.getLong("expiryDate") ?: -1
        subscription.protocols = oocResponse.getStringArray("protocols")
            ?: error("missing protocols")
        subscription.applyDefaultValues()

        for (protocol in subscription.protocols) {
            if (protocol !in supportedProtocols) {
                userInterface?.alert(app.getString(R.string.ooc_missing_protocol, protocol))
            }
        }

        var profiles = mutableListOf<AbstractBean>()

        val pattern = Regex(subscription.nameFilter)
        for (protocol in subscription.protocols) {
            val profilesInProtocol = oocResponse.getArray(protocol)
                ?: error("missing protocol $protocol settings")

            if (protocol == "shadowsocks") for (profile in profilesInProtocol) {
                val bean = ShadowsocksBean()

                bean.name = profile.getString("name")
                bean.serverAddress = profile.getString("address") ?: error("missing address")
                bean.serverPort = profile.getInt("port") ?: error("missing port")
                bean.method = profile.getString("method") ?: error("missing method")
                bean.password = profile.getString("password")

                val pluginId = when (val id = profile.getString("pluginName")) {
                    "simple-obfs" -> "obfs-local"
                    else -> id
                }
                if (!pluginId.isNullOrEmpty()) {
                    // TODO: check plugin exists
                    // TODO: check pluginVersion
                    // TODO: support pluginArguments
                    bean.plugin = PluginOptions(pluginId, profile.getString("pluginOptions")).toString(trimId = false)
                }

                appendExtraInfo(profile, bean)

                if (subscription.nameFilter.isEmpty() || !pattern.containsMatchIn(bean.name)) {
                    profiles.add(bean)
                }
            }
        }

        profiles.forEach { it.applyDefaultValues() }

        val exists = SagerDatabase.proxyDao.getByGroup(proxyGroup.id)
        val duplicate = ArrayList<String>()
        if (subscription.deduplication) {
            val uniqueProfiles = LinkedHashSet<AbstractBean>()
            val uniqueNames = HashMap<AbstractBean, String>()
            for (proxy in profiles) {
                if (!uniqueProfiles.add(proxy)) {
                    val index = uniqueProfiles.indexOf(proxy)
                    if (uniqueNames.containsKey(proxy)) {
                        val name = uniqueNames[proxy]!!.replace(" ($index)", "")
                        if (name.isNotEmpty()) {
                            duplicate.add("$name ($index)")
                            uniqueNames[proxy] = ""
                        }
                    }
                    duplicate.add(proxy.displayName() + " ($index)")
                } else {
                    uniqueNames[proxy] = proxy.displayName()
                }
            }
            uniqueProfiles.retainAll(uniqueNames.keys)
            profiles = uniqueProfiles.toMutableList()
        }

        val profileMap = profiles.associateBy { it.profileId }
        val toDelete = ArrayList<ProxyEntity>()
        val toReplace = exists.mapNotNull { entity ->
            val profileId = entity.requireBean().profileId
            if (profileMap.contains(profileId)) profileId to entity else let {
                toDelete.add(entity)
                null
            }
        }.toMap()

        val toUpdate = ArrayList<ProxyEntity>()
        val added = mutableListOf<String>()
        val updated = mutableMapOf<String, String>()
        val deleted = toDelete.map { it.displayName() }

        var userOrder = 1L
        var changed = toDelete.size
        for ((profileId, bean) in profileMap.entries) {
            val name = bean.displayName()
            if (toReplace.contains(profileId)) {
                val entity = toReplace[profileId]!!
                val existsBean = entity.requireBean()
                existsBean.applyFeatureSettings(bean)
                when {
                    existsBean != bean -> {
                        changed++
                        entity.putBean(bean)
                        toUpdate.add(entity)
                        updated[entity.displayName()] = name
                    }
                    entity.userOrder != userOrder -> {
                        entity.putBean(bean)
                        toUpdate.add(entity)
                        entity.userOrder = userOrder
                    }
                }
            } else {
                changed++
                SagerDatabase.proxyDao.addProxy(ProxyEntity(
                    groupId = proxyGroup.id, userOrder = userOrder
                ).apply {
                    putBean(bean)
                })
                added.add(name)
            }
            userOrder++
        }

        SagerDatabase.proxyDao.updateProxy(toUpdate)
        SagerDatabase.proxyDao.deleteProxy(toDelete)

        subscription.lastUpdated = System.currentTimeMillis() / 1000
        SagerDatabase.groupDao.updateGroup(proxyGroup)
        finishUpdate(proxyGroup)

        userInterface?.onUpdateSuccess(
            proxyGroup, changed, added, updated, deleted, duplicate, byUser
        )
    }

    fun appendExtraInfo(profile: JsonObject, bean: AbstractBean) {
        bean.extraType = ExtraType.OOCv1
        bean.profileId = profile.getString("id")
        bean.group = profile.getString("group")
        bean.owner = profile.getString("owner")
        bean.tags = profile.getStringArray("tags")
    }

    val supportedProtocols = arrayOf("shadowsocks")

}