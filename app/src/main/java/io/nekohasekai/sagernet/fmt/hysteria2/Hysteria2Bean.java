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
    public String pinSHA256;
    public String caText;
    public Boolean allowInsecure;
    public Integer uploadMbps;
    public Integer downloadMbps;
    public Boolean disableMtuDiscovery;
    public Integer initStreamReceiveWindow;
    public Integer maxStreamReceiveWindow;
    public Integer initConnReceiveWindow;
    public Integer maxConnReceiveWindow;
    public String serverPorts;
    public Integer hopInterval;

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
        if (pinSHA256 == null) pinSHA256 = "";
        if (caText == null) caText = "";
        if (allowInsecure == null) allowInsecure = false;
        if (uploadMbps == null) uploadMbps = 0;
        if (downloadMbps == null) downloadMbps = 0;
        if (disableMtuDiscovery == null) disableMtuDiscovery = false;
        if (initStreamReceiveWindow == null) initStreamReceiveWindow = 0;
        if (maxStreamReceiveWindow == null) maxStreamReceiveWindow = 0;
        if (initConnReceiveWindow == null) initConnReceiveWindow = 0;
        if (maxConnReceiveWindow == null) maxConnReceiveWindow = 0;
        if (serverPorts == null) serverPorts = "1080";
        if (hopInterval == null) hopInterval = 30;
    }

    @Override
    public void serialize(ByteBufferOutput output) {
        output.writeInt(2);
        super.serialize(output);
        output.writeString(auth);
        output.writeString(obfs);
        output.writeString(sni);
        output.writeString(pinSHA256);
        output.writeString(caText);
        output.writeBoolean(allowInsecure);
        output.writeInt(uploadMbps);
        output.writeInt(downloadMbps);
        output.writeBoolean(disableMtuDiscovery);
        output.writeInt(initStreamReceiveWindow);
        output.writeInt(maxStreamReceiveWindow);
        output.writeInt(initConnReceiveWindow);
        output.writeInt(maxConnReceiveWindow);
        output.writeString(serverPorts);
        output.writeInt(hopInterval);
    }

    @Override
    public void deserialize(ByteBufferInput input) {
        int version = input.readInt();
        super.deserialize(input);
        auth = input.readString();
        obfs = input.readString();
        sni = input.readString();
        pinSHA256 = input.readString();
        caText = input.readString();
        allowInsecure = input.readBoolean();
        uploadMbps = input.readInt();
        downloadMbps = input.readInt();
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
            hopInterval = input.readInt();
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
        bean.caText = caText;
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
            return serverAddress + ":" + serverPorts;
        }
    }

    @Override
    public String network() {
        return "udp";
    }

    @Override
    public boolean canTCPing() {
        return false;
    }

    @NotNull
    @Override
    public Hysteria2Bean clone() {
        return KryoConverters.deserialize(new Hysteria2Bean(), KryoConverters.serialize(this));
    }

    public static final Creator<Hysteria2Bean> CREATOR = new CREATOR<Hysteria2Bean>() {
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
