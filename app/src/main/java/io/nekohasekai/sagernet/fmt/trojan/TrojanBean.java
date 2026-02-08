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

package io.nekohasekai.sagernet.fmt.trojan;

import androidx.annotation.NonNull;

import com.esotericsoftware.kryo.io.ByteBufferInput;
import com.esotericsoftware.kryo.io.ByteBufferOutput;

import org.jetbrains.annotations.NotNull;

import io.nekohasekai.sagernet.fmt.AbstractBean;
import io.nekohasekai.sagernet.fmt.KryoConverters;
import io.nekohasekai.sagernet.fmt.v2ray.StandardV2RayBean;

public class TrojanBean extends StandardV2RayBean {

    public String password;

    @Override
    public void initializeDefaultValues() {
        super.initializeDefaultValues();
        if (password == null) password = "";
    }

    @Override
    public void serialize(ByteBufferOutput output) {
        output.writeInt(2);
        super.serialize(output);
        output.writeString(password);
    }

    @Override
    public void deserialize(ByteBufferInput input) {
        int version = input.readInt();
        if (version >= 2) {
            super.deserialize(input);
            password = input.readString();
        } else {
            serverAddress = input.readString();
            serverPort = input.readInt();
            password = input.readString();
            security = input.readString();
            sni = input.readString();
            alpn = input.readString();
            if (version == 1) {
                if ("tls".equals(security)) {
                    allowInsecure = input.readBoolean();
                } else {
                    security = "tls"; // xtls, removed, for compatibility
                    input.readString(); // flow, removed
                }
            }
        }
    }

    @NotNull
    @Override
    public TrojanBean clone() {
        return KryoConverters.deserialize(new TrojanBean(), KryoConverters.serialize(this));
    }

    public static final Creator<TrojanBean> CREATOR = new CREATOR<>() {
        @NonNull
        @Override
        public TrojanBean newInstance() {
            return new TrojanBean();
        }

        @Override
        public TrojanBean[] newArray(int size) {
            return new TrojanBean[size];
        }
    };
}
