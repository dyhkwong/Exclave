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

import com.github.shadowsocks.plugin.PluginConfiguration;
import com.github.shadowsocks.plugin.PluginOptions;

import java.util.Objects;

import io.nekohasekai.sagernet.fmt.AbstractBean;
import io.nekohasekai.sagernet.fmt.KryoConverters;
import io.nekohasekai.sagernet.fmt.v2ray.StandardV2RayBean;

public class ShadowsocksBean extends StandardV2RayBean {

    public String method;
    public String password;
    public String plugin;
    public Boolean experimentReducedIvHeadEntropy;
    public Boolean singUoT;

    @Override
    public void initializeDefaultValues() {
        super.initializeDefaultValues();

        if (method == null) method = "none";
        if (password == null) password = "";
        if (plugin == null) plugin = "";
        if (experimentReducedIvHeadEntropy == null) experimentReducedIvHeadEntropy = false;
        if (singUoT == null) singUoT = false;
    }

    @Override
    public boolean canMapping() {
        if (plugin.isEmpty()) {
            return super.canMapping();
        }
        PluginConfiguration pluginConfiguration = new PluginConfiguration(plugin);
        if (pluginConfiguration.getSelected().isEmpty()) {
            return super.canMapping();
        }
        return false;
    }

    @Override
    public void serialize(ByteBufferOutput output) {
        output.writeInt(6);
        super.serialize(output);
        output.writeString(method);
        output.writeString(password);
        output.writeString(plugin);
        output.writeBoolean(experimentReducedIvHeadEntropy);
        output.writeBoolean(singUoT);
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
        if (version >= 6) {
            singUoT = input.readBoolean();
        }
    }

    public String protocolName() {
        if (method.startsWith("2022-blake3-")) {
            return "Shadowsocks 2022";
        } else {
            return "Shadowsocks";
        }
    }

    @Override
    public void applyFeatureSettings(AbstractBean other) {
        if (!(other instanceof ShadowsocksBean bean)) return;
        bean.experimentReducedIvHeadEntropy = experimentReducedIvHeadEntropy;
        bean.singUoT = singUoT;
    }

    @NotNull
    @Override
    public ShadowsocksBean clone() {
        return KryoConverters.deserialize(new ShadowsocksBean(), KryoConverters.serialize(this));
    }

    public static final Creator<ShadowsocksBean> CREATOR = new CREATOR<>() {
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

    @Override
    public boolean isInsecure() {
        if (!plugin.isEmpty()) {
            PluginConfiguration pluginConfiguration = new PluginConfiguration(plugin);
            String selectedPlugin = pluginConfiguration.getSelected();
            switch (selectedPlugin) {
                case "", "obfs-local":
                    break;
                case "v2ray-plugin":
                    PluginOptions pluginOptions = pluginConfiguration.getOptions(selectedPlugin, () -> null);
                    if (pluginOptions.containsKey("tls")) {
                        return false;
                    }
                    if (Objects.equals(pluginOptions.get("mode"), "quic")) {
                        return false;
                    }
                    break;
                default:
                    // Can not check if plugin is insecure or not
                    return false;
            }
        }
        switch (method) {
            case "aes-128-gcm", "aes-192-gcm", "aes-256-gcm", "chacha20-poly1305", "xchacha20-poly1305",
                 "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305":
                return false;
        }
        return super.isInsecure();
    }

}
