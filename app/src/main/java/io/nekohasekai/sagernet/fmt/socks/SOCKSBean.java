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

package io.nekohasekai.sagernet.fmt.socks;

import androidx.annotation.NonNull;

import com.esotericsoftware.kryo.io.ByteBufferInput;
import com.esotericsoftware.kryo.io.ByteBufferOutput;

import org.jetbrains.annotations.NotNull;

import io.nekohasekai.sagernet.fmt.AbstractBean;
import io.nekohasekai.sagernet.fmt.KryoConverters;
import io.nekohasekai.sagernet.fmt.v2ray.StandardV2RayBean;

public class SOCKSBean extends StandardV2RayBean {

    public Integer protocol;

    public int protocolVersion() {
        switch (protocol) {
            case 0:
            case 1:
                return 4;
            default:
                return 5;
        }
    }

    public String protocolName() {
        switch (protocol) {
            case 0:
                return "SOCKS4";
            case 1:
                return "SOCKS4A";
            default:
                return "SOCKS5";
        }
    }

    public String protocolVersionName() {
        switch (protocol) {
            case 0:
                return "4";
            case 1:
                return "4a";
            default:
                return "5";
        }
    }

    public String username;
    public String password;

    public static final int PROTOCOL_SOCKS4 = 0;
    public static final int PROTOCOL_SOCKS4A = 1;
    public static final int PROTOCOL_SOCKS5 = 2;

    public Boolean singUoT;

    @Override
    public void initializeDefaultValues() {
        super.initializeDefaultValues();

        if (protocol == null) protocol = PROTOCOL_SOCKS5;
        if (username == null) username = "";
        if (password == null) password = "";
        if (singUoT == null) singUoT = false;
    }

    @Override
    public void serialize(ByteBufferOutput output) {
        output.writeInt(4);
        super.serialize(output);
        output.writeInt(protocol);
        output.writeString(username);
        output.writeString(password);
        output.writeBoolean(singUoT);
    }

    @Override
    public void deserialize(ByteBufferInput input) {
        int version = input.readInt();
        if (version >= 3) {
            super.deserialize(input);
        } else {
            serverAddress = input.readString();
            serverPort = input.readInt();
        }
        if (version >= 1) {
            protocol = input.readInt();
        }
        username = input.readString();
        password = input.readString();
        if (version <= 2) {
            if (input.readBoolean()) {
                security = "tls";
            }
            sni = input.readString();
        }
        if (version == 2) {
            utlsFingerprint = input.readString();
        }
        if (version >= 4) {
            singUoT = input.readBoolean();
        }
    }

    @Override
    public void applyFeatureSettings(AbstractBean other) {
        if (!(other instanceof SOCKSBean bean)) return;
        bean.singUoT = singUoT;
    }

    @NotNull
    @Override
    public SOCKSBean clone() {
        return KryoConverters.deserialize(new SOCKSBean(), KryoConverters.serialize(this));
    }

    public static final Creator<SOCKSBean> CREATOR = new CREATOR<SOCKSBean>() {
        @NonNull
        @Override
        public SOCKSBean newInstance() {
            return new SOCKSBean();
        }

        @Override
        public SOCKSBean[] newArray(int size) {
            return new SOCKSBean[size];
        }
    };

}
