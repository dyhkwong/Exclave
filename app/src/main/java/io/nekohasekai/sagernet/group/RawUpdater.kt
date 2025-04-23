package io.nekohasekai.sagernet.group

import androidx.core.net.toUri
import cn.hutool.json.JSONObject
import cn.hutool.json.JSONUtil
import io.nekohasekai.sagernet.R
import io.nekohasekai.sagernet.SagerNet
import io.nekohasekai.sagernet.database.DataStore
import io.nekohasekai.sagernet.database.GroupManager
import io.nekohasekai.sagernet.database.ProxyEntity
import io.nekohasekai.sagernet.database.ProxyGroup
import io.nekohasekai.sagernet.database.SagerDatabase
import io.nekohasekai.sagernet.database.SubscriptionBean
import io.nekohasekai.sagernet.fmt.AbstractBean
import io.nekohasekai.sagernet.fmt.shadowsocks.parseShadowsocksConfig
import io.nekohasekai.sagernet.fmt.wireguard.parseWireGuardConfig
import io.nekohasekai.sagernet.ktx.decodeBase64UrlSafe
import io.nekohasekai.sagernet.ktx.parseShareLinks
import io.nekohasekai.sagernet.ktx.*
import libcore.Libcore
import org.yaml.snakeyaml.TypeDescription
import org.yaml.snakeyaml.Yaml

@Suppress("EXPERIMENTAL_API_USAGE")
object RawUpdater : GroupUpdater() {

    override suspend fun doUpdate(
        proxyGroup: ProxyGroup,
        subscription: SubscriptionBean,
        userInterface: GroupManager.Interface?,
        byUser: Boolean
    ) {

        val link = subscription.link
        var proxies: List<AbstractBean>
        if (link.startsWith("content://")) {
            val contentText = app.contentResolver.openInputStream(link.toUri())
                ?.bufferedReader()
                ?.readText()

            proxies = contentText?.let { parseRaw(contentText) }
                ?: error(app.getString(R.string.no_proxies_found_in_subscription))
        } else {
            val response = Libcore.newHttpClient().apply {
                if (SagerNet.started && DataStore.startedProfile > 0) {
                    useSocks5(DataStore.socksPort)
                }
            }.newRequest().apply {
                setURL(subscription.link)
                if (subscription.customUserAgent.isNotEmpty()) {
                    setUserAgent(subscription.customUserAgent)
                } else {
                    setUserAgent(USER_AGENT)
                }
            }.execute()

            proxies = parseRaw(response.contentString)
                ?: error(app.getString(R.string.no_proxies_found))

            val subscriptionUserinfo = response.getHeader("Subscription-Userinfo")
            if (subscriptionUserinfo.isNotEmpty()) {
                fun get(regex: String): String? {
                    return regex.toRegex().findAll(subscriptionUserinfo).mapNotNull {
                        if (it.groupValues.size > 1) it.groupValues[1] else null
                    }.firstOrNull()
                }
                var used = 0L
                try {
                    val upload = get("upload=([0-9]+)")?.toLong() ?: -1L
                    if (upload > 0L) {
                        used += upload
                    }
                    val download = get("download=([0-9]+)")?.toLong() ?: -1L
                    if (download > 0L) {
                        used += download
                    }
                    val total = get("total=([0-9]+)")?.toLong() ?: -1L
                    subscription.apply {
                        if (upload > 0L || download > 0L) {
                            bytesUsed = used
                            bytesRemaining = if (total > 0L) total - used else -1L
                        } else {
                            bytesUsed = -1L
                            bytesRemaining = -1L
                        }
                        expiryDate = get("expire=([0-9]+)")?.toLong() ?: -1L
                    }
                } catch (_: Exception) {
                }
            } else {
                subscription.apply {
                    bytesUsed = -1L
                    bytesRemaining = -1L
                    expiryDate = -1L
                }
            }
        }

        if (subscription.nameFilter.isNotEmpty()) {
            val pattern = Regex(subscription.nameFilter)
            proxies = proxies.filter { !pattern.containsMatchIn(it.name) }
        }

        proxies.forEach { it.applyDefaultValues() }

        val proxiesMap = LinkedHashMap<String, AbstractBean>()
        for (proxy in proxies) {
            var index = 0
            var name = proxy.displayName()
            while (proxiesMap.containsKey(name)) {
                println("Exists name: $name")
                index++
                name = name.replace(" (${index - 1})", "")
                name = "$name ($index)"
                proxy.name = name
            }
            proxiesMap[proxy.displayName()] = proxy
        }
        proxies = proxiesMap.values.toList()

        val exists = SagerDatabase.proxyDao.getByGroup(proxyGroup.id)
        val duplicate = ArrayList<String>()
        if (subscription.deduplication) {
            Logs.d("Before deduplication: ${proxies.size}")
            val uniqueProxies = LinkedHashSet<Protocols.Deduplication>()
            val uniqueNames = HashMap<Protocols.Deduplication, String>()
            for (p in proxies) {
                val proxy = Protocols.Deduplication(p, p.javaClass.toString())
                if (!uniqueProxies.add(proxy)) {
                    val index = uniqueProxies.indexOf(proxy)
                    if (uniqueNames.containsKey(proxy)) {
                        val name = uniqueNames[proxy]!!.replace(" ($index)", "")
                        if (name.isNotEmpty()) {
                            duplicate.add("$name ($index)")
                            uniqueNames[proxy] = ""
                        }
                    }
                    duplicate.add(p.displayName() + " ($index)")
                } else {
                    uniqueNames[proxy] = p.displayName()
                }
            }
            uniqueProxies.retainAll(uniqueNames.keys)
            proxies = uniqueProxies.toList().map { it.bean }
        }

        Logs.d("New profiles: ${proxies.size}")

        val nameMap = proxies.associateBy { bean ->
            bean.displayName()
        }

        Logs.d("Unique profiles: ${nameMap.size}")

        val toDelete = ArrayList<ProxyEntity>()
        val toReplace = exists.mapNotNull { entity ->
            val name = entity.displayName()
            if (nameMap.contains(name)) name to entity else let {
                toDelete.add(entity)
                null
            }
        }.toMap()

        Logs.d("toDelete profiles: ${toDelete.size}")
        Logs.d("toReplace profiles: ${toReplace.size}")

        val toUpdate = ArrayList<ProxyEntity>()
        val added = mutableListOf<String>()
        val updated = mutableMapOf<String, String>()
        val deleted = toDelete.map { it.displayName() }

        var userOrder = 1L
        var changed = toDelete.size
        for ((name, bean) in nameMap.entries) {
            if (toReplace.contains(name)) {
                val entity = toReplace[name]!!
                val existsBean = entity.requireBean()
                existsBean.applyFeatureSettings(bean)
                when {
                    existsBean != bean -> {
                        changed++
                        entity.putBean(bean)
                        toUpdate.add(entity)
                        updated[entity.displayName()] = name

                        Logs.d("Updated profile: $name")
                    }
                    entity.userOrder != userOrder -> {
                        entity.putBean(bean)
                        toUpdate.add(entity)
                        entity.userOrder = userOrder

                        Logs.d("Reordered profile: $name")
                    }
                    else -> {
                        Logs.d("Ignored profile: $name")
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
                Logs.d("Inserted profile: $name")
            }
            userOrder++
        }

        SagerDatabase.proxyDao.updateProxy(toUpdate).also {
            Logs.d("Updated profiles: $it")
        }

        SagerDatabase.proxyDao.deleteProxy(toDelete).also {
            Logs.d("Deleted profiles: $it")
        }

        val existCount = SagerDatabase.proxyDao.countByGroup(proxyGroup.id).toInt()

        if (existCount != proxies.size) {
            Logs.e("Exist profiles: $existCount, new profiles: ${proxies.size}")
        }

        subscription.lastUpdated = System.currentTimeMillis() / 1000
        SagerDatabase.groupDao.updateGroup(proxyGroup)
        finishUpdate(proxyGroup)

        userInterface?.onUpdateSuccess(
            proxyGroup, changed, added, updated, deleted, duplicate, byUser
        )
    }

    @Suppress("UNCHECKED_CAST")
    fun parseRaw(text: String): List<AbstractBean>? {
        if (text.contains("proxies")) {
            try {
                (Yaml().apply {
                    addTypeDescription(TypeDescription(String::class.java, "str"))
                }.loadAs(text, Map::class.java)["proxies"] as? List<Map<String, Any?>>)?.let { proxies ->
                    val beans = mutableListOf<AbstractBean>()
                    proxies.forEach {
                        beans.addAll(parseClashProxies(it))
                    }
                    return beans.takeIf { it.isNotEmpty() }
                }
            } catch (_: Exception) {}
        }
        if (text.contains("[Interface]")) {
            try {
                parseWireGuardConfig(text).takeIf { it.isNotEmpty() }?.let {
                    return it
                }
            } catch (_: Exception) {}
        }
        try {
            JSONUtil.parse(Libcore.stripJSON(text))?.let { json ->
                if (json !is JSONObject) return null
                return parseJSONConfig(json).takeIf { it.isNotEmpty() }
            }
        } catch (_: Exception) {}
        try {
            parseShareLinks(text.decodeBase64UrlSafe()).takeIf { it.isNotEmpty() }?.let {
                return it
            }
        } catch (e: SubscriptionFoundException) {
            throw(e)
        } catch (_: Exception) {}
        try {
            parseShareLinks(text).takeIf { it.isNotEmpty() }?.let {
                return it
            }
        } catch (e: SubscriptionFoundException) {
            throw(e)
        } catch (_: Exception) {}
        return null
    }

    @Suppress("UNCHECKED_CAST")
    private fun parseJSONConfig(json: JSONObject): List<AbstractBean> {
        when {
            json.getInt("version") != null && json.containsKey("servers") -> {
                val beans = ArrayList<AbstractBean>()
                (json.getJSONArray("servers") as? List<JSONObject>)?.forEach { server ->
                    server.parseShadowsocksConfig()?.let {
                        beans.add(it)
                    }
                }
                return beans
            }
            json.containsKey("method") -> {
                json.parseShadowsocksConfig()?.let {
                    return listOf(it)
                } ?: return ArrayList()
            }
            json.contains("type") -> {
                return parseSingBoxEndpoint(json).takeIf { it.isNotEmpty() }
                    ?: parseSingBoxOutbound(json)
            }
            json.contains("protocol") -> {
                return parseV2ray5Outbound(json).takeIf { it.isNotEmpty() }
                    ?: parseV2RayOutbound(json)
            }
            else -> {
                val beans = ArrayList<AbstractBean>()
                json.getArray("endpoints")?.filterIsInstance<JSONObject>()?.forEach { endpoint ->
                    beans.addAll(parseSingBoxEndpoint(endpoint))
                }
                json.getArray("outbounds")?.filterIsInstance<JSONObject>()?.forEach { outbound ->
                    when {
                        outbound.contains("protocol") -> {
                            beans.addAll(
                                parseV2ray5Outbound(outbound).takeIf { it.isNotEmpty() } ?:
                                parseV2RayOutbound(outbound)
                            )
                        }
                        outbound.contains("type") -> {
                            beans.addAll(parseSingBoxOutbound(outbound))
                        }
                    }
                }
                return beans
            }
        }
    }
}