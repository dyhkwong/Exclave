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

package io.nekohasekai.sagernet.fmt.hysteria;

import androidx.annotation.NonNull;

import com.esotericsoftware.kryo.io.ByteBufferInput;
import com.esotericsoftware.kryo.io.ByteBufferOutput;

import org.jetbrains.annotations.NotNull;

import io.nekohasekai.sagernet.database.DataStore;
import io.nekohasekai.sagernet.fmt.AbstractBean;
import io.nekohasekai.sagernet.fmt.KryoConverters;
import io.nekohasekai.sagernet.ktx.NetsKt;
import libcore.Libcore;

public class HysteriaBean extends AbstractBean {

    public static final int TYPE_NONE = 0;
    public static final int TYPE_STRING = 1;
    public static final int TYPE_BASE64 = 2;

    public Integer authPayloadType;
    public String authPayload;

    public static final int PROTOCOL_UDP = 0;
    public static final int PROTOCOL_FAKETCP = 1;
    public static final int PROTOCOL_WECHAT_VIDEO = 2;

    public Integer protocol;

    public String obfuscation;
    public String sni;
    public String alpn;
    public String caText;

    public Long uploadMbps;
    public Long downloadMbps;
    public Boolean allowInsecure;
    public Integer streamReceiveWindow;
    public Integer connectionReceiveWindow;
    public Boolean disableMtuDiscovery;

    public String serverPorts;
    public Long hopInterval;

    @Override
    public boolean canMapping() {
        if (protocol == PROTOCOL_FAKETCP) {
            return false;
        }
        if (!DataStore.INSTANCE.getHysteriaEnablePortHopping()) {
            return true;
        }
        return !NetsKt.isValidHysteriaMultiPort(serverPorts, false);
    }

    @Override
    public boolean needProtect() {
        if (!DataStore.INSTANCE.getHysteriaEnablePortHopping()) {
            return false;
        }
        return NetsKt.isValidHysteriaMultiPort(serverPorts, false);
    }

    @Override
    public boolean needBypassRootUID() {
        return protocol == PROTOCOL_FAKETCP;
    }

    @Override
    public void initializeDefaultValues() {
        super.initializeDefaultValues();
        if (authPayloadType == null) authPayloadType = TYPE_NONE;
        if (authPayload == null) authPayload = "";
        if (protocol == null) protocol = PROTOCOL_UDP;
        if (obfuscation == null) obfuscation = "";
        if (sni == null) sni = "";
        if (alpn == null) alpn = "";
        if (caText == null) caText = "";

        if (uploadMbps == null) uploadMbps = 10L;
        if (downloadMbps == null) downloadMbps = 50L;
        if (allowInsecure == null) allowInsecure = false;

        if (streamReceiveWindow == null) streamReceiveWindow = 0;
        if (connectionReceiveWindow == null) connectionReceiveWindow = 0;
        if (disableMtuDiscovery == null) disableMtuDiscovery = false;

        if (serverPorts == null) serverPorts = "1080";
        if (hopInterval == null) hopInterval = 0L;
    }

    @Override
    public void serialize(ByteBufferOutput output) {
        output.writeInt(7);
        super.serialize(output);
        output.writeInt(authPayloadType);
        output.writeString(authPayload);
        output.writeInt(protocol);
        output.writeString(obfuscation);
        output.writeString(sni);
        output.writeString(alpn);

        output.writeLong(uploadMbps);
        output.writeLong(downloadMbps);
        output.writeBoolean(allowInsecure);

        output.writeString(caText);
        output.writeInt(streamReceiveWindow);
        output.writeInt(connectionReceiveWindow);
        output.writeBoolean(disableMtuDiscovery);

        output.writeString(serverPorts);
        output.writeLong(hopInterval);
    }

    @Override
    public void deserialize(ByteBufferInput input) {
        int version = input.readInt();
        super.deserialize(input);
        authPayloadType = input.readInt();
        authPayload = input.readString();
        if (version >= 3) {
            protocol = input.readInt();
        }
        obfuscation = input.readString();
        sni = input.readString();
        if (version >= 2) {
            alpn = input.readString();
        }
        if (version <= 6) {
            uploadMbps = (long) input.readInt();
        } else {
            uploadMbps = input.readLong();
        }
        if (version <= 6) {
            downloadMbps = (long) input.readInt();
        } else {
            downloadMbps = input.readLong();
        }
        allowInsecure = input.readBoolean();
        if (version >= 1) {
            caText = input.readString();
            streamReceiveWindow = input.readInt();
            connectionReceiveWindow = input.readInt();
            if (version != 4) {
                disableMtuDiscovery = input.readBoolean();
            }
        }
        if (version < 6) {
            serverPorts = serverPort.toString();
        }
        if (version >= 6) {
            serverPorts = input.readString();
            if (version == 6) {
                hopInterval = (long) input.readInt();
            } else {
                hopInterval = input.readLong();
            }
        }
    }

    @Override
    public void applyFeatureSettings(AbstractBean other) {
        if (!(other instanceof HysteriaBean bean)) return;
        if (allowInsecure) {
            bean.allowInsecure = true;
        }
        bean.uploadMbps = uploadMbps;
        bean.downloadMbps = downloadMbps;
        bean.disableMtuDiscovery = disableMtuDiscovery;
        bean.streamReceiveWindow = streamReceiveWindow;
        bean.connectionReceiveWindow = connectionReceiveWindow;
        bean.hopInterval = hopInterval;
        bean.caText = caText;
    }

    @Override
    public String displayAddress() {
        if (Libcore.isIPv6(serverAddress)) {
            return "[" + serverAddress + "]:" + serverPorts;
        } else {
            return NetsKt.wrapIDN(serverAddress) + ":" + serverPorts;
        }
    }

    @Override
    public String network() {
        return "udp"; // "faketcp" does not use this
    }

    @NotNull
    @Override
    public HysteriaBean clone() {
        return KryoConverters.deserialize(new HysteriaBean(), KryoConverters.serialize(this));
    }

    public static final Creator<HysteriaBean> CREATOR = new CREATOR<HysteriaBean>() {
        @NonNull
        @Override
        public HysteriaBean newInstance() {
            return new HysteriaBean();
        }

        @Override
        public HysteriaBean[] newArray(int size) {
            return new HysteriaBean[size];
        }
    };
}
