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

package io.nekohasekai.sagernet.fmt.http;

import androidx.annotation.NonNull;

import com.esotericsoftware.kryo.io.ByteBufferInput;
import com.esotericsoftware.kryo.io.ByteBufferOutput;

import org.jetbrains.annotations.NotNull;

import io.nekohasekai.sagernet.fmt.AbstractBean;
import io.nekohasekai.sagernet.fmt.KryoConverters;
import io.nekohasekai.sagernet.fmt.v2ray.StandardV2RayBean;

public class HttpBean extends StandardV2RayBean {

    public String username;
    public String password;
    public Boolean trustTunnelUot; // Deprecated. Do not use.

    @Override
    public void initializeDefaultValues() {
        super.initializeDefaultValues();
        if (username == null) username = "";
        if (password == null) password = "";
        if (trustTunnelUot == null) trustTunnelUot = false;
    }

    @Override
    public void serialize(ByteBufferOutput output) {
        output.writeInt(3);
        super.serialize(output);
        output.writeString(username);
        output.writeString(password);
        output.writeBoolean(trustTunnelUot);
    }

    @Override
    public void deserialize(ByteBufferInput input) {
        int version = input.readInt();
        if (version >= 2) {
            super.deserialize(input);
        } else {
            serverAddress = input.readString();
            serverPort = input.readInt();
        }
        username = input.readString();
        password = input.readString();
        if (version <= 1) {
            if (input.readBoolean()) {
                security = "tls";
            }
            sni = input.readString();
            utlsFingerprint = input.readString();
        }
        if (version >= 3) {
            trustTunnelUot = input.readBoolean();
        }
    }

    public String protocolName() {
        if (security.equals("tls")) {
            return "HTTPS";
        } else {
            return "HTTP";
        }
    }

    @Override
    public void applyFeatureSettings(AbstractBean other) {
        if (!(other instanceof HttpBean bean)) return;
        bean.trustTunnelUot = trustTunnelUot;
    }

    @NotNull
    @Override
    public HttpBean clone() {
        return KryoConverters.deserialize(new HttpBean(), KryoConverters.serialize(this));
    }

    public static final Creator<HttpBean> CREATOR = new CREATOR<HttpBean>() {
        @NonNull
        @Override
        public HttpBean newInstance() {
            return new HttpBean();
        }

        @Override
        public HttpBean[] newArray(int size) {
            return new HttpBean[size];
        }
    };
}
