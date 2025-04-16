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

package io.nekohasekai.sagernet.fmt.shadowsocks;

import androidx.annotation.NonNull;

import com.esotericsoftware.kryo.io.ByteBufferInput;
import com.esotericsoftware.kryo.io.ByteBufferOutput;

import org.jetbrains.annotations.NotNull;

import io.nekohasekai.sagernet.fmt.AbstractBean;
import io.nekohasekai.sagernet.fmt.KryoConverters;
import io.nekohasekai.sagernet.fmt.v2ray.StandardV2RayBean;

public class ShadowsocksBean extends StandardV2RayBean {

    public String method;
    public String password;
    public String plugin;
    public Boolean experimentReducedIvHeadEntropy;

    @Override
    public void initializeDefaultValues() {
        super.initializeDefaultValues();

        if (method == null) method = "none";
        if (password == null) password = "";
        if (plugin == null) plugin = "";
        if (experimentReducedIvHeadEntropy == null) experimentReducedIvHeadEntropy = false;
    }

    @Override
    public void serialize(ByteBufferOutput output) {
        output.writeInt(5);
        super.serialize(output);
        output.writeString(method);
        output.writeString(password);
        output.writeString(plugin);
        output.writeBoolean(experimentReducedIvHeadEntropy);
    }

    @Override
    public void deserialize(ByteBufferInput input) {
        int version = input.readInt();
        if (version >= 5) {
            super.deserialize(input);
        } else {
            serverAddress = input.readString();
            serverPort = input.readInt();
        }
        method = input.readString();
        password = input.readString();
        plugin = input.readString();
        if (version >= 1) {
            experimentReducedIvHeadEntropy = input.readBoolean();
        }
        if (version == 2 || version == 3) {
            input.readBoolean(); // uot, removed
        }
        if (version == 3) {
            input.readBoolean(); // encryptedProtocolExtension, removed
        }
    }

    @Override
    public void applyFeatureSettings(AbstractBean other) {
        if (!(other instanceof ShadowsocksBean bean)) return;
        bean.experimentReducedIvHeadEntropy = experimentReducedIvHeadEntropy;
    }

    @NotNull
    @Override
    public ShadowsocksBean clone() {
        return KryoConverters.deserialize(new ShadowsocksBean(), KryoConverters.serialize(this));
    }

    public static final Creator<ShadowsocksBean> CREATOR = new CREATOR<ShadowsocksBean>() {
        @NonNull
        @Override
        public ShadowsocksBean newInstance() {
            return new ShadowsocksBean();
        }

        @Override
        public ShadowsocksBean[] newArray(int size) {
            return new ShadowsocksBean[size];
        }
    };
}
