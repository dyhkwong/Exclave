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

package io.nekohasekai.sagernet.fmt.hysteria2;

import androidx.annotation.NonNull;

import com.esotericsoftware.kryo.io.ByteBufferInput;
import com.esotericsoftware.kryo.io.ByteBufferOutput;

import org.jetbrains.annotations.NotNull;

import io.nekohasekai.sagernet.ProtocolProvider;
import io.nekohasekai.sagernet.database.DataStore;
import io.nekohasekai.sagernet.fmt.AbstractBean;
import io.nekohasekai.sagernet.fmt.KryoConverters;
import io.nekohasekai.sagernet.ktx.NetsKt;

public class Hysteria2Bean extends AbstractBean {

    public String auth;
    public String obfs;
    public String sni;
    public String pinnedPeerCertificateSha256;
    public String pinnedPeerCertificatePublicKeySha256;
    public String pinnedPeerCertificateChainSha256;
    public String certificates;
    public Boolean allowInsecure;
    public Long uploadMbps;
    public Long downloadMbps;
    public Boolean disableMtuDiscovery;
    public Integer initStreamReceiveWindow;
    public Integer maxStreamReceiveWindow;
    public Integer initConnReceiveWindow;
    public Integer maxConnReceiveWindow;
    public String serverPorts;
    public Long hopInterval;
    public String echConfig;
    public String mtlsCertificate;
    public String mtlsCertificatePrivateKey;

    @Override
    public boolean canMapping() {
        if (!DataStore.INSTANCE.getHysteriaEnablePortHopping()) {
            return true;
        }
        return !NetsKt.isValidHysteriaMultiPort(serverPorts);
    }

    @Override
    public boolean needProtect() {
        if (DataStore.INSTANCE.getProviderHysteria2() == ProtocolProvider.CORE) {
            return false;
        }
        return !canMapping();
    }

    @Override
    public void initializeDefaultValues() {
        super.initializeDefaultValues();
        if (auth == null) auth = "";
        if (obfs == null) obfs = "";
        if (sni == null) sni = "";
        if (pinnedPeerCertificateSha256 == null) pinnedPeerCertificateSha256 = "";
        if (pinnedPeerCertificatePublicKeySha256 == null) pinnedPeerCertificatePublicKeySha256 = "";
        if (pinnedPeerCertificateChainSha256 == null) pinnedPeerCertificateChainSha256 = "";
        if (certificates == null) certificates = "";
        if (allowInsecure == null) allowInsecure = false;
        if (uploadMbps == null) uploadMbps = 0L;
        if (downloadMbps == null) downloadMbps = 0L;
        if (disableMtuDiscovery == null) disableMtuDiscovery = false;
        if (initStreamReceiveWindow == null) initStreamReceiveWindow = 0;
        if (maxStreamReceiveWindow == null) maxStreamReceiveWindow = 0;
        if (initConnReceiveWindow == null) initConnReceiveWindow = 0;
        if (maxConnReceiveWindow == null) maxConnReceiveWindow = 0;
        if (serverPorts == null) serverPorts = "1080";
        if (hopInterval == null) hopInterval = 0L;
        if (echConfig == null) echConfig = "";
        if (mtlsCertificate == null) mtlsCertificate = "";
        if (mtlsCertificatePrivateKey == null) mtlsCertificatePrivateKey = "";
    }

    @Override
    public void serialize(ByteBufferOutput output) {
        output.writeInt(4);
        super.serialize(output);
        output.writeString(auth);
        output.writeString(obfs);
        output.writeString(sni);
        output.writeString(pinnedPeerCertificateSha256);
        output.writeString(pinnedPeerCertificatePublicKeySha256);
        output.writeString(pinnedPeerCertificateChainSha256);
        output.writeString(certificates);
        output.writeBoolean(allowInsecure);
        output.writeLong(uploadMbps);
        output.writeLong(downloadMbps);
        output.writeBoolean(disableMtuDiscovery);
        output.writeInt(initStreamReceiveWindow);
        output.writeInt(maxStreamReceiveWindow);
        output.writeInt(initConnReceiveWindow);
        output.writeInt(maxConnReceiveWindow);
        output.writeString(serverPorts);
        output.writeLong(hopInterval);
        output.writeString(echConfig);
        output.writeString(mtlsCertificate);
        output.writeString(mtlsCertificatePrivateKey);
    }

    @Override
    public void deserialize(ByteBufferInput input) {
        int version = input.readInt();
        super.deserialize(input);
        auth = input.readString();
        obfs = input.readString();
        sni = input.readString();
        pinnedPeerCertificateSha256 = input.readString();
        if (version >= 4) {
            pinnedPeerCertificatePublicKeySha256 = input.readString();
            pinnedPeerCertificateChainSha256 = input.readString();
        }
        certificates = input.readString();
        allowInsecure = input.readBoolean();
        if (version <= 2) {
            uploadMbps = (long) input.readInt();
        } else {
            uploadMbps = input.readLong();
        }
        if (version <= 2) {
            downloadMbps = (long) input.readInt();
        } else {
            downloadMbps = input.readLong();
        }
        disableMtuDiscovery = input.readBoolean();
        initStreamReceiveWindow = input.readInt();
        maxStreamReceiveWindow = input.readInt();
        initConnReceiveWindow = input.readInt();
        maxConnReceiveWindow = input.readInt();
        if (version < 2) {
            serverPorts = serverPort.toString();
        }
        if (version >= 2) {
            serverPorts = input.readString();
            if (version == 2) {
                hopInterval = (long) input.readInt();
            } else {
                hopInterval = input.readLong();
            }
        }
        if (version >= 4) {
            echConfig = input.readString();
            mtlsCertificate = input.readString();
            mtlsCertificatePrivateKey = input.readString();
        }
    }

    @Override
    public void applyFeatureSettings(AbstractBean other) {
        if (!(other instanceof Hysteria2Bean bean)) return;
        if (allowInsecure) {
            bean.allowInsecure = true;
        }
        bean.uploadMbps = uploadMbps;
        bean.downloadMbps = downloadMbps;
        bean.disableMtuDiscovery = disableMtuDiscovery;
        if (bean.pinnedPeerCertificateSha256 == null || bean.pinnedPeerCertificateSha256.isEmpty() && !pinnedPeerCertificateSha256.isEmpty()) {
            bean.pinnedPeerCertificateSha256 = pinnedPeerCertificateSha256;
        }
        if (bean.pinnedPeerCertificatePublicKeySha256 == null || bean.pinnedPeerCertificatePublicKeySha256.isEmpty() &&
                !pinnedPeerCertificatePublicKeySha256.isEmpty()) {
            bean.pinnedPeerCertificatePublicKeySha256 = pinnedPeerCertificatePublicKeySha256;
        }
        if (bean.pinnedPeerCertificateChainSha256 == null || bean.pinnedPeerCertificateChainSha256.isEmpty() &&
                !pinnedPeerCertificateChainSha256.isEmpty()) {
            bean.pinnedPeerCertificateChainSha256 = pinnedPeerCertificateChainSha256;
        }
        if (bean.certificates == null || bean.certificates.isEmpty() && !certificates.isEmpty()) {
            bean.certificates = certificates;
        }
        bean.echConfig = echConfig;
        bean.hopInterval = hopInterval;
        bean.initConnReceiveWindow = initConnReceiveWindow;
        bean.initStreamReceiveWindow = initStreamReceiveWindow;
        bean.maxConnReceiveWindow = maxConnReceiveWindow;
        bean.maxStreamReceiveWindow = maxStreamReceiveWindow;
    }

    @Override
    public String displayAddress() {
        if (NetsKt.isIpv6Address(serverAddress)) {
            return "[" + serverAddress + "]:" + serverPorts;
        } else {
            return NetsKt.wrapIDN(serverAddress) + ":" + serverPorts;
        }
    }

    @Override
    public String network() {
        return "udp";
    }

    public boolean canUsePluginImplementation() {
        if (!NetsKt.listByLineOrComma(pinnedPeerCertificatePublicKeySha256).isEmpty()) {
            return false;
        }
        if (!NetsKt.listByLineOrComma(pinnedPeerCertificateChainSha256).isEmpty()) {
            return false;
        }
        if (NetsKt.listByLineOrComma(pinnedPeerCertificateSha256).size() > 1) {
            return false;
        }
        if (!NetsKt.listByLineOrComma(echConfig).isEmpty()) {
            return false;
        }
        return true;
    }

    @NotNull
    @Override
    public Hysteria2Bean clone() {
        return KryoConverters.deserialize(new Hysteria2Bean(), KryoConverters.serialize(this));
    }

    public static final Creator<Hysteria2Bean> CREATOR = new CREATOR<>() {
        @NonNull
        @Override
        public Hysteria2Bean newInstance() {
            return new Hysteria2Bean();
        }

        @Override
        public Hysteria2Bean[] newArray(int size) {
            return new Hysteria2Bean[size];
        }
    };
}
