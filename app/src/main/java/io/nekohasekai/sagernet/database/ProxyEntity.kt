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

package io.nekohasekai.sagernet.database

import android.content.Context
import android.content.Intent
import androidx.room.*
import com.esotericsoftware.kryo.io.ByteBufferInput
import com.esotericsoftware.kryo.io.ByteBufferOutput
import io.nekohasekai.sagernet.R
import io.nekohasekai.sagernet.TrojanProvider
import io.nekohasekai.sagernet.Hysteria2Provider
import io.nekohasekai.sagernet.aidl.TrafficStats
import io.nekohasekai.sagernet.fmt.AbstractBean
import io.nekohasekai.sagernet.fmt.KryoConverters
import io.nekohasekai.sagernet.fmt.Serializable
import io.nekohasekai.sagernet.fmt.brook.BrookBean
import io.nekohasekai.sagernet.fmt.brook.toUri
import io.nekohasekai.sagernet.fmt.buildV2RayConfig
import io.nekohasekai.sagernet.fmt.http.HttpBean
import io.nekohasekai.sagernet.fmt.http.toUri
import io.nekohasekai.sagernet.fmt.hysteria.HysteriaBean
import io.nekohasekai.sagernet.fmt.hysteria.buildHysteriaConfig
import io.nekohasekai.sagernet.fmt.hysteria.toUri
import io.nekohasekai.sagernet.fmt.hysteria2.Hysteria2Bean
import io.nekohasekai.sagernet.fmt.hysteria2.buildHysteria2Config
import io.nekohasekai.sagernet.fmt.hysteria2.toUri
import io.nekohasekai.sagernet.fmt.internal.BalancerBean
import io.nekohasekai.sagernet.fmt.internal.ChainBean
import io.nekohasekai.sagernet.fmt.internal.ConfigBean
import io.nekohasekai.sagernet.fmt.juicity.buildJuicityConfig
import io.nekohasekai.sagernet.fmt.juicity.JuicityBean
import io.nekohasekai.sagernet.fmt.juicity.toUri
import io.nekohasekai.sagernet.fmt.mieru.MieruBean
import io.nekohasekai.sagernet.fmt.mieru.buildMieruConfig
import io.nekohasekai.sagernet.fmt.mieru2.Mieru2Bean
import io.nekohasekai.sagernet.fmt.mieru2.buildMieru2Config
import io.nekohasekai.sagernet.fmt.naive.NaiveBean
import io.nekohasekai.sagernet.fmt.naive.buildNaiveConfig
import io.nekohasekai.sagernet.fmt.naive.toUri
import io.nekohasekai.sagernet.fmt.pingtunnel.PingTunnelBean
import io.nekohasekai.sagernet.fmt.pingtunnel.toUri
import io.nekohasekai.sagernet.fmt.relaybaton.RelayBatonBean
import io.nekohasekai.sagernet.fmt.relaybaton.buildRelayBatonConfig
import io.nekohasekai.sagernet.fmt.shadowsocks.ShadowsocksBean
import io.nekohasekai.sagernet.fmt.shadowsocks.toUri
import io.nekohasekai.sagernet.fmt.shadowsocksr.ShadowsocksRBean
import io.nekohasekai.sagernet.fmt.shadowsocksr.toUri
import io.nekohasekai.sagernet.fmt.socks.SOCKSBean
import io.nekohasekai.sagernet.fmt.socks.toUri
import io.nekohasekai.sagernet.fmt.ssh.SSHBean
import io.nekohasekai.sagernet.fmt.toUniversalLink
import io.nekohasekai.sagernet.fmt.trojan.TrojanBean
import io.nekohasekai.sagernet.fmt.trojan.toUri
import io.nekohasekai.sagernet.fmt.trojan_go.TrojanGoBean
import io.nekohasekai.sagernet.fmt.trojan_go.buildTrojanGoConfig
import io.nekohasekai.sagernet.fmt.trojan_go.toUri
import io.nekohasekai.sagernet.fmt.tuic.TuicBean
import io.nekohasekai.sagernet.fmt.tuic.buildTuicConfig
import io.nekohasekai.sagernet.fmt.tuic5.Tuic5Bean
import io.nekohasekai.sagernet.fmt.tuic5.buildTuic5Config
import io.nekohasekai.sagernet.fmt.shadowtls.ShadowTLSBean
import io.nekohasekai.sagernet.fmt.v2ray.StandardV2RayBean
import io.nekohasekai.sagernet.fmt.v2ray.VLESSBean
import io.nekohasekai.sagernet.fmt.v2ray.VMessBean
import io.nekohasekai.sagernet.fmt.v2ray.toUri
import io.nekohasekai.sagernet.fmt.wireguard.WireGuardBean
import io.nekohasekai.sagernet.ktx.Logs
import io.nekohasekai.sagernet.ktx.app
import io.nekohasekai.sagernet.ktx.applyDefaultValues
import io.nekohasekai.sagernet.ui.profile.*

@Entity(
    tableName = "proxy_entities", indices = [Index("groupId", name = "groupId")]
)
data class ProxyEntity(
    @PrimaryKey(autoGenerate = true) var id: Long = 0L,
    var groupId: Long = 0L,
    var type: Int = 0,
    var userOrder: Long = 0L,
    var tx: Long = 0L,
    var rx: Long = 0L,
    var status: Int = 0,
    var ping: Int = 0,
    var uuid: String = "",
    var error: String? = null,
    var socksBean: SOCKSBean? = null,
    var httpBean: HttpBean? = null,
    var ssBean: ShadowsocksBean? = null,
    var ssrBean: ShadowsocksRBean? = null,
    var vmessBean: VMessBean? = null,
    var vlessBean: VLESSBean? = null,
    var trojanBean: TrojanBean? = null,
    var trojanGoBean: TrojanGoBean? = null,
    var naiveBean: NaiveBean? = null,
    var ptBean: PingTunnelBean? = null,
    var rbBean: RelayBatonBean? = null,
    var brookBean: BrookBean? = null,
    var hysteriaBean: HysteriaBean? = null,
    var hysteria2Bean: Hysteria2Bean? = null,
    var mieruBean: MieruBean? = null,
    var mieru2Bean: Mieru2Bean? = null,
    var tuicBean: TuicBean? = null,
    var tuic5Bean: Tuic5Bean? = null,
    var shadowtlsBean: ShadowTLSBean? = null,
    var sshBean: SSHBean? = null,
    var wgBean: WireGuardBean? = null,
    var juicityBean: JuicityBean? = null,
    var configBean: ConfigBean? = null,
    var chainBean: ChainBean? = null,
    var balancerBean: BalancerBean? = null
) : Serializable() {

    companion object {
        const val TYPE_SOCKS = 0
        const val TYPE_HTTP = 1
        const val TYPE_SS = 2
        const val TYPE_SSR = 3
        const val TYPE_VMESS = 4
        const val TYPE_VLESS = 5
        const val TYPE_TROJAN = 6
        const val TYPE_TROJAN_GO = 7
        const val TYPE_NAIVE = 9
        const val TYPE_PING_TUNNEL = 10
        const val TYPE_RELAY_BATON = 11
        const val TYPE_BROOK = 12
        const val TYPE_HYSTERIA = 15
        const val TYPE_HYSTERIA2 = 21
        const val TYPE_SNELL = 16
        const val TYPE_SSH = 17
        const val TYPE_WG = 18
        const val TYPE_MIERU = 19
        const val TYPE_MIERU2 = 22
        const val TYPE_TUIC = 20
        const val TYPE_TUIC5 = 23
        const val TYPE_SHADOWTLS = 24
        const val TYPE_JUICITY = 25

        const val TYPE_CHAIN = 8
        const val TYPE_BALANCER = 14
        const val TYPE_CONFIG = 13

        val chainName by lazy { app.getString(R.string.proxy_chain) }
        val configName by lazy { app.getString(R.string.custom_config) }
        val balancerName by lazy { app.getString(R.string.balancer) }

        private val placeHolderBean = SOCKSBean().applyDefaultValues()

        @JvmField
        val CREATOR = object : CREATOR<ProxyEntity>() {

            override fun newInstance(): ProxyEntity {
                return ProxyEntity()
            }

            override fun newArray(size: Int): Array<ProxyEntity?> {
                return arrayOfNulls(size)
            }
        }
    }

    @Ignore
    @Transient
    var dirty: Boolean = false

    @Ignore
    @Transient
    var stats: TrafficStats? = null

    override fun initializeDefaultValues() {
    }

    override fun serializeToBuffer(output: ByteBufferOutput) {
        output.writeInt(0)

        output.writeLong(id)
        output.writeLong(groupId)
        output.writeInt(type)
        output.writeLong(userOrder)
        output.writeLong(tx)
        output.writeLong(rx)
        output.writeInt(status)
        output.writeInt(ping)
        output.writeString(uuid)
        output.writeString(error)

        val data = KryoConverters.serialize(requireBean())
        output.writeVarInt(data.size, true)
        output.writeBytes(data)

        output.writeBoolean(dirty)
    }

    override fun deserializeFromBuffer(input: ByteBufferInput) {
        val version = input.readInt()

        id = input.readLong()
        groupId = input.readLong()
        type = input.readInt()
        userOrder = input.readLong()
        tx = input.readLong()
        rx = input.readLong()
        status = input.readInt()
        ping = input.readInt()
        uuid = input.readString()
        error = input.readString()
        putByteArray(input.readBytes(input.readVarInt(true)))

        dirty = input.readBoolean()
    }


    fun putByteArray(byteArray: ByteArray) {
        when (type) {
            TYPE_SOCKS -> socksBean = KryoConverters.socksDeserialize(byteArray)
            TYPE_HTTP -> httpBean = KryoConverters.httpDeserialize(byteArray)
            TYPE_SS -> ssBean = KryoConverters.shadowsocksDeserialize(byteArray)
            TYPE_SSR -> ssrBean = KryoConverters.shadowsocksRDeserialize(byteArray)
            TYPE_VMESS -> vmessBean = KryoConverters.vmessDeserialize(byteArray)
            TYPE_VLESS -> vlessBean = KryoConverters.vlessDeserialize(byteArray)
            TYPE_TROJAN -> trojanBean = KryoConverters.trojanDeserialize(byteArray)
            TYPE_TROJAN_GO -> trojanGoBean = KryoConverters.trojanGoDeserialize(byteArray)
            TYPE_NAIVE -> naiveBean = KryoConverters.naiveDeserialize(byteArray)
            TYPE_PING_TUNNEL -> ptBean = KryoConverters.pingTunnelDeserialize(byteArray)
            TYPE_RELAY_BATON -> rbBean = KryoConverters.relayBatonDeserialize(byteArray)
            TYPE_BROOK -> brookBean = KryoConverters.brookDeserialize(byteArray)
            TYPE_HYSTERIA -> hysteriaBean = KryoConverters.hysteriaDeserialize(byteArray)
            TYPE_HYSTERIA2 -> hysteria2Bean = KryoConverters.hysteria2Deserialize(byteArray)
            TYPE_SSH -> sshBean = KryoConverters.sshDeserialize(byteArray)
            TYPE_WG -> wgBean = KryoConverters.wireguardDeserialize(byteArray)
            TYPE_MIERU -> mieruBean = KryoConverters.mieruDeserialize(byteArray)
            TYPE_MIERU2 -> mieru2Bean = KryoConverters.mieru2Deserialize(byteArray)
            TYPE_TUIC -> tuicBean = KryoConverters.tuicDeserialize(byteArray)
            TYPE_TUIC5 -> tuic5Bean = KryoConverters.tuic5Deserialize(byteArray)
            TYPE_SHADOWTLS -> shadowtlsBean = KryoConverters.shadowtlsDeserialize(byteArray)
            TYPE_JUICITY -> juicityBean = KryoConverters.juicityDeserialize(byteArray)

            TYPE_CONFIG -> configBean = KryoConverters.configDeserialize(byteArray)
            TYPE_CHAIN -> chainBean = KryoConverters.chainDeserialize(byteArray)
            TYPE_BALANCER -> balancerBean = KryoConverters.balancerBeanDeserialize(byteArray)
        }
    }

    fun displayType() = when (type) {
        TYPE_SOCKS -> socksBean!!.protocolName()
        TYPE_HTTP -> if (httpBean!!.security == "tls") "HTTPS" else "HTTP"
        TYPE_SS -> if (ssBean!!.method.startsWith("2022-blake3-")) "Shadowsocks 2022" else "Shadowsocks"
        TYPE_SSR -> "ShadowsocksR"
        TYPE_VMESS -> "VMess"
        TYPE_VLESS -> "VLESS"
        TYPE_TROJAN -> "Trojan"
        TYPE_TROJAN_GO -> "Trojan-Go"
        TYPE_NAIVE -> "Naïve"
        TYPE_PING_TUNNEL -> "PingTunnel"
        TYPE_RELAY_BATON -> "relaybaton"
        TYPE_BROOK -> "Brook"
        TYPE_HYSTERIA -> "Hysteria"
        TYPE_HYSTERIA2 -> "Hysteria2"
        TYPE_SNELL -> "Snell"
        TYPE_SSH -> "SSH"
        TYPE_WG -> "WireGuard"
        TYPE_MIERU -> "Mieru"
        TYPE_MIERU2 -> "Mieru2"
        TYPE_TUIC -> "TUIC"
        TYPE_TUIC5 -> "TUIC v5"
        TYPE_SHADOWTLS -> "ShadowTLS"
        TYPE_JUICITY -> "Juicity"

        TYPE_CHAIN -> chainName
        TYPE_CONFIG -> configName
        TYPE_BALANCER -> balancerName
        else -> "Invalid"
    }

    fun displayName() = requireBean().displayName()
    fun displayAddress() = requireBean().displayAddress()

    fun requireBean(): AbstractBean {
        return when (type) {
            TYPE_SOCKS -> socksBean
            TYPE_HTTP -> httpBean
            TYPE_SS -> ssBean
            TYPE_SSR -> ssrBean
            TYPE_VMESS -> vmessBean
            TYPE_VLESS -> vlessBean
            TYPE_TROJAN -> trojanBean
            TYPE_TROJAN_GO -> trojanGoBean
            TYPE_NAIVE -> naiveBean
            TYPE_PING_TUNNEL -> ptBean
            TYPE_RELAY_BATON -> rbBean
            TYPE_BROOK -> brookBean
            TYPE_HYSTERIA -> hysteriaBean
            TYPE_HYSTERIA2 -> hysteria2Bean
            TYPE_SSH -> sshBean
            TYPE_WG -> wgBean
            TYPE_MIERU -> mieruBean
            TYPE_MIERU2 -> mieru2Bean
            TYPE_TUIC -> tuicBean
            TYPE_TUIC5 -> tuic5Bean
            TYPE_SHADOWTLS -> shadowtlsBean
            TYPE_JUICITY -> juicityBean

            TYPE_CONFIG -> configBean
            TYPE_CHAIN -> chainBean
            TYPE_BALANCER -> balancerBean
            else -> null
        } ?: SOCKSBean().applyDefaultValues()
    }

    fun haveLink(): Boolean {
        return when (type) {
            TYPE_CHAIN -> false
            TYPE_BALANCER -> false
            else -> true
        }
    }

    fun haveStandardLink(): Boolean {
        return haveLink() && when (type) {
            TYPE_RELAY_BATON, TYPE_SSH, TYPE_WG, TYPE_MIERU, TYPE_MIERU2, TYPE_TUIC, TYPE_TUIC5, TYPE_SHADOWTLS -> false
            TYPE_CONFIG -> false
            else -> true
        }
    }

    fun toLink(): String? = with(requireBean()) {
        when (this) {
            is SOCKSBean -> toUri()
            is HttpBean -> toUri()
            is ShadowsocksBean -> toUri()
            is ShadowsocksRBean -> toUri()
            is VMessBean -> toUri()
            is VLESSBean -> toUri()
            is TrojanBean -> toUri()
            is TrojanGoBean -> toUri()
            is NaiveBean -> toUri()
            is PingTunnelBean -> toUri()
            is HysteriaBean -> toUri()
            is Hysteria2Bean -> toUri()
            is BrookBean -> toUri()
            is JuicityBean -> toUri()

            is RelayBatonBean -> toUniversalLink()
            is ConfigBean -> toUniversalLink()
            is SSHBean -> toUniversalLink()
            is WireGuardBean -> toUniversalLink()
            is MieruBean -> toUniversalLink()
            is Mieru2Bean -> toUniversalLink()
            is TuicBean -> toUniversalLink()
            is Tuic5Bean -> toUniversalLink()
            is ShadowTLSBean -> toUniversalLink()
            else -> null
        }
    }

    fun exportConfig(): Pair<String, String> {
        var name = "${displayName()}.json"

        return with(requireBean()) {
            StringBuilder().apply {
                val config = buildV2RayConfig(this@ProxyEntity)
                append(config.config)

                if (!config.index.all { it.chain.isEmpty() }) {
                    name = "${displayName()}.txt"
                }

                val enableMux = DataStore.enableMux
                for ((isBalancer, chain) in config.index) {
                    chain.entries.forEachIndexed { index, (port, profile) ->
                        val needChain = !isBalancer && index != chain.size - 1
                        val needMux = enableMux && (isBalancer || index == chain.size - 1)
                        when (val bean = profile.requireBean()) {
                            is TrojanGoBean -> {
                                append("\n\n")
                                append(bean.buildTrojanGoConfig(port, needMux).also {
                                    Logs.d(it)
                                })
                            }
                            is NaiveBean -> {
                                append("\n\n")
                                append(bean.buildNaiveConfig(port).also {
                                    Logs.d(it)
                                })
                            }
                            is RelayBatonBean -> {
                                append("\n\n")
                                append(bean.buildRelayBatonConfig(port).also {
                                    Logs.d(it)
                                })
                            }
                            is HysteriaBean -> {
                                append("\n\n")
                                append(bean.buildHysteriaConfig(port, null).also {
                                    Logs.d(it)
                                })
                            }
                            is Hysteria2Bean -> {
                                append("\n\n")
                                append(bean.buildHysteria2Config(port, null).also {
                                    Logs.d(it)
                                })
                            }
                            is MieruBean -> {
                                append("\n\n")
                                append(bean.buildMieruConfig(port).also {
                                    Logs.d(it)
                                })
                            }
                            is Mieru2Bean -> {
                                append("\n\n")
                                append(bean.buildMieru2Config(port).also {
                                    Logs.d(it)
                                })
                            }
                            is TuicBean -> {
                                append("\n\n")
                                append(bean.buildTuicConfig(port, null).also {
                                    Logs.d(it)
                                })
                            }
                            is Tuic5Bean -> {
                                append("\n\n")
                                append(bean.buildTuic5Config(port, null).also {
                                    Logs.d(it)
                                })
                            }
                            is JuicityBean -> {
                                append("\n\n")
                                append(bean.buildJuicityConfig(port).also {
                                    Logs.d(it)
                                })
                            }
                        }
                    }
                }
            }.toString()
        } to name
    }

    fun needExternal(): Boolean {
        val bean = requireBean()
        if (bean is ConfigBean) {
            return bean.type != "v2ray_outbound"
        }
        if (bean is Hysteria2Bean) {
            return DataStore.providerHysteria2 != Hysteria2Provider.V2RAY || !bean.canMapping()
        }
        return when (type) {
            TYPE_TROJAN_GO -> true
            TYPE_NAIVE -> true
            TYPE_PING_TUNNEL -> true
            TYPE_HYSTERIA -> true
            TYPE_RELAY_BATON -> true
            TYPE_BROOK -> true
            TYPE_MIERU -> true
            TYPE_MIERU2 -> true
            TYPE_TUIC -> true
            TYPE_TUIC5 -> true
            TYPE_SHADOWTLS -> true
            TYPE_JUICITY -> true

            else -> false
        }
    }

    fun isV2RayNetworkTcp(): Boolean {
        val bean = requireBean() as StandardV2RayBean
        return when (bean.type) {
            "tcp", "ws", "http", "grpc", "httpupgrade", "meek", "splithttp" -> true
            else -> false
        }
    }

    fun needCoreMux(): Boolean {
        val enableMuxForAll by lazy { DataStore.enableMuxForAll }
        return when (type) {
            TYPE_VMESS, TYPE_VLESS -> isV2RayNetworkTcp()
            TYPE_TROJAN_GO -> false
            else -> enableMuxForAll
        }
    }

    fun putBean(bean: AbstractBean): ProxyEntity {
        socksBean = null
        httpBean = null
        ssBean = null
        ssrBean = null
        vmessBean = null
        vlessBean = null
        trojanBean = null
        trojanGoBean = null
        naiveBean = null
        ptBean = null
        rbBean = null
        brookBean = null
        hysteriaBean = null
        hysteria2Bean = null
        sshBean = null
        wgBean = null
        mieruBean = null
        mieru2Bean = null
        tuicBean = null
        tuic5Bean = null
        shadowtlsBean = null
        juicityBean = null

        configBean = null
        chainBean = null
        balancerBean = null

        when (bean) {
            is SOCKSBean -> {
                type = TYPE_SOCKS
                socksBean = bean
            }
            is HttpBean -> {
                type = TYPE_HTTP
                httpBean = bean
            }
            is ShadowsocksBean -> {
                type = TYPE_SS
                ssBean = bean
            }
            is ShadowsocksRBean -> {
                type = TYPE_SSR
                ssrBean = bean
            }
            is VMessBean -> {
                type = TYPE_VMESS
                vmessBean = bean
            }
            is VLESSBean -> {
                type = TYPE_VLESS
                vlessBean = bean
            }
            is TrojanBean -> {
                type = TYPE_TROJAN
                trojanBean = bean
            }
            is TrojanGoBean -> {
                type = TYPE_TROJAN_GO
                trojanGoBean = bean
            }
            is NaiveBean -> {
                type = TYPE_NAIVE
                naiveBean = bean
            }
            is PingTunnelBean -> {
                type = TYPE_PING_TUNNEL
                ptBean = bean
            }
            is RelayBatonBean -> {
                type = TYPE_RELAY_BATON
                rbBean = bean
            }
            is BrookBean -> {
                type = TYPE_BROOK
                brookBean = bean
            }
            is HysteriaBean -> {
                type = TYPE_HYSTERIA
                hysteriaBean = bean
            }
            is Hysteria2Bean -> {
                type = TYPE_HYSTERIA2
                hysteria2Bean = bean
            }
            is SSHBean -> {
                type = TYPE_SSH
                sshBean = bean
            }
            is WireGuardBean -> {
                type = TYPE_WG
                wgBean = bean
            }
            is MieruBean -> {
                type = TYPE_MIERU
                mieruBean = bean
            }
            is Mieru2Bean -> {
                type = TYPE_MIERU2
                mieru2Bean = bean
            }
            is TuicBean -> {
                type = TYPE_TUIC
                tuicBean = bean
            }
            is Tuic5Bean -> {
                type = TYPE_TUIC5
                tuic5Bean = bean
            }
            is ShadowTLSBean -> {
                type = TYPE_SHADOWTLS
                shadowtlsBean = bean
            }
            is JuicityBean -> {
                type = TYPE_JUICITY
                juicityBean = bean
            }

            is ConfigBean -> {
                type = TYPE_CONFIG
                configBean = bean
            }
            is ChainBean -> {
                type = TYPE_CHAIN
                chainBean = bean
            }
            is BalancerBean -> {
                type = TYPE_BALANCER
                balancerBean = bean
            }
            else -> error("Undefined type $type")
        }
        return this
    }

    fun settingIntent(ctx: Context, isSubscription: Boolean): Intent {
        return Intent(
            ctx, when (type) {
                TYPE_SOCKS -> SocksSettingsActivity::class.java
                TYPE_HTTP -> HttpSettingsActivity::class.java
                TYPE_SS -> ShadowsocksSettingsActivity::class.java
                TYPE_SSR -> ShadowsocksRSettingsActivity::class.java
                TYPE_VMESS -> VMessSettingsActivity::class.java
                TYPE_VLESS -> VLESSSettingsActivity::class.java
                TYPE_TROJAN -> TrojanSettingsActivity::class.java
                TYPE_TROJAN_GO -> TrojanGoSettingsActivity::class.java
                TYPE_NAIVE -> NaiveSettingsActivity::class.java
                TYPE_PING_TUNNEL -> PingTunnelSettingsActivity::class.java
                TYPE_RELAY_BATON -> RelayBatonSettingsActivity::class.java
                TYPE_BROOK -> BrookSettingsActivity::class.java
                TYPE_HYSTERIA -> HysteriaSettingsActivity::class.java
                TYPE_HYSTERIA2 -> Hysteria2SettingsActivity::class.java
                TYPE_SSH -> SSHSettingsActivity::class.java
                TYPE_WG -> WireGuardSettingsActivity::class.java
                TYPE_MIERU -> MieruSettingsActivity::class.java
                TYPE_MIERU2 -> Mieru2SettingsActivity::class.java
                TYPE_TUIC -> TuicSettingsActivity::class.java
                TYPE_TUIC5 -> Tuic5SettingsActivity::class.java
                TYPE_SHADOWTLS -> ShadowTLSSettingsActivity::class.java
                TYPE_JUICITY -> JuicitySettingsActivity::class.java

                TYPE_CONFIG -> ConfigSettingsActivity::class.java
                TYPE_CHAIN -> ChainSettingsActivity::class.java
                TYPE_BALANCER -> BalancerSettingsActivity::class.java
                else -> throw IllegalArgumentException()
            }
        ).apply {
            putExtra(ProfileSettingsActivity.EXTRA_PROFILE_ID, id)
            putExtra(ProfileSettingsActivity.EXTRA_IS_SUBSCRIPTION, isSubscription)
        }
    }

    @androidx.room.Dao
    interface Dao {

        @Query("select * from proxy_entities")
        fun getAll(): List<ProxyEntity>

        @Query("SELECT id FROM proxy_entities WHERE groupId = :groupId ORDER BY userOrder")
        fun getIdsByGroup(groupId: Long): List<Long>

        @Query("SELECT * FROM proxy_entities WHERE groupId = :groupId ORDER BY userOrder")
        fun getByGroup(groupId: Long): List<ProxyEntity>

        @Query("SELECT * FROM proxy_entities WHERE id in (:proxyIds)")
        fun getEntities(proxyIds: List<Long>): List<ProxyEntity>

        @Query("SELECT COUNT(*) FROM proxy_entities WHERE groupId = :groupId")
        fun countByGroup(groupId: Long): Long

        @Query("SELECT  MAX(userOrder) + 1 FROM proxy_entities WHERE groupId = :groupId")
        fun nextOrder(groupId: Long): Long?

        @Query("SELECT * FROM proxy_entities WHERE id = :proxyId")
        fun getById(proxyId: Long): ProxyEntity?

        @Query("DELETE FROM proxy_entities WHERE id IN (:proxyId)")
        fun deleteById(proxyId: Long): Int

        @Query("DELETE FROM proxy_entities WHERE groupId = :groupId")
        fun deleteByGroup(groupId: Long)

        @Query("DELETE FROM proxy_entities WHERE groupId in (:groupId)")
        fun deleteByGroup(groupId: LongArray)

        @Delete
        fun deleteProxy(proxy: ProxyEntity): Int

        @Delete
        fun deleteProxy(proxies: List<ProxyEntity>): Int

        @Update
        fun updateProxy(proxy: ProxyEntity): Int

        @Update
        fun updateProxy(proxies: List<ProxyEntity>): Int

        @Insert
        fun addProxy(proxy: ProxyEntity): Long

        @Insert
        fun insert(proxies: List<ProxyEntity>)

        @Query("DELETE FROM proxy_entities WHERE groupId = :groupId")
        fun deleteAll(groupId: Long): Int

        @Query("DELETE FROM proxy_entities")
        fun reset()

    }

    override fun describeContents(): Int {
        return 0
    }
}