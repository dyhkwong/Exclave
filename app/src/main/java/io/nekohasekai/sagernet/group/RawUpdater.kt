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
import io.nekohasekai.sagernet.ktx.*
import libcore.Libcore
import org.yaml.snakeyaml.DumperOptions
import org.yaml.snakeyaml.LoaderOptions
import org.yaml.snakeyaml.TypeDescription
import org.yaml.snakeyaml.Yaml
import org.yaml.snakeyaml.constructor.Constructor
import org.yaml.snakeyaml.nodes.Tag
import org.yaml.snakeyaml.representer.Representer
import org.yaml.snakeyaml.resolver.Resolver
import java.util.regex.Pattern

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

        val nameMap = proxies.associateBy { bean ->
            bean.displayName()
        }

        val toDelete = ArrayList<ProxyEntity>()
        val toReplace = exists.mapNotNull { entity ->
            val name = entity.displayName()
            if (nameMap.contains(name)) name to entity else let {
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

    @Suppress("UNCHECKED_CAST")
    fun parseRaw(text: String): List<AbstractBean>? {
        try {
            val options = DumperOptions()
            val yaml = Yaml(Constructor(LoaderOptions()), Representer(options), options, object : Resolver() {
                override fun addImplicitResolver(tag: Tag, regexp: Pattern, first: String?, limit: Int) {
                    // Stupid config providers write ambiguous strings without quoting.
                    when (tag) {
                        Tag.FLOAT, Tag.BINARY, Tag.TIMESTAMP -> null // Clash does not use these types for `proxies`
                        Tag.INT -> null // Treat as str
                        Tag.BOOL -> super.addImplicitResolver(tag, Pattern.compile("^(?:true|True|TRUE|false|False|FALSE)$"), "tTfF", limit)
                        else -> super.addImplicitResolver(tag, regexp, first, limit)
                    }
                }
            }).apply {
                addTypeDescription(TypeDescription(String::class.java, "str"))
            }.loadAs(text, Map::class.java)
            (yaml["proxies"] as? List<Map<String, Any?>>)?.let {
                return parseClashProxies(it)
            }
        } catch (_: Exception) {}
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
        try {
            parseWireGuardConfig(text).takeIf { it.isNotEmpty() }?.let {
                return it
            }
        } catch (_: Exception) {}
        return null
    }

    @Suppress("UNCHECKED_CAST")
    private fun parseJSONConfig(json: JSONObject): List<AbstractBean> {
        when {
            json.containsKey("proxies") -> {
                // Clash YAML
                return listOf()
            }
            json.getInt("version") != null && json.containsKey("servers") -> {
                // SIP008
                val beans = ArrayList<AbstractBean>()
                (json["servers"] as? List<Map<String, Any?>>)?.forEach { server ->
                    parseShadowsocksConfig(server)?.let {
                        beans.add(it)
                    }
                }
                return beans
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
                json.getArray("endpoints")?.forEach { endpoint ->
                    beans.addAll(parseSingBoxEndpoint(endpoint))
                }
                json.getArray("outbounds")?.forEach { outbound ->
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