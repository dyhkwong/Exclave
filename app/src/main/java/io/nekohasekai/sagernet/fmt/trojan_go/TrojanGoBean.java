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

package io.nekohasekai.sagernet.fmt.trojan_go;

import androidx.annotation.NonNull;

import com.esotericsoftware.kryo.io.ByteBufferInput;
import com.esotericsoftware.kryo.io.ByteBufferOutput;

import org.jetbrains.annotations.NotNull;

import io.nekohasekai.sagernet.fmt.AbstractBean;
import io.nekohasekai.sagernet.fmt.KryoConverters;

public class TrojanGoBean extends AbstractBean {

    public String password;
    public String sni;
    public String type;
    public String host;
    public String path;
    public String encryption;

    public Boolean allowInsecure;
    public String utlsFingerprint;

    public Boolean mux;
    public Integer muxConcurrency;

    @Override
    public void initializeDefaultValues() {
        super.initializeDefaultValues();

        if (password == null) password = "";
        if (sni == null) sni = "";
        if (type == null) type = "none";
        if (host == null) host = "";
        if (path == null) path = "";
        if (encryption == null) encryption = "none";
        if (allowInsecure == null) allowInsecure = false;
        if (utlsFingerprint == null) utlsFingerprint = "";
        if (mux == null) mux = false;
        if (muxConcurrency == null) muxConcurrency = 8;
    }

    @Override
    public void serialize(ByteBufferOutput output) {
        output.writeInt(5);
        super.serialize(output);
        output.writeString(password);
        output.writeString(sni);
        output.writeString(type);
        //noinspection SwitchStatementWithTooFewBranches
        switch (type) {
            case "ws": {
                output.writeString(host);
                output.writeString(path);
                break;
            }
        }
        output.writeString(encryption);
        output.writeBoolean(allowInsecure);
        output.writeString(utlsFingerprint);
        output.writeBoolean(mux);
        output.writeInt(muxConcurrency);
    }

    @Override
    public void deserialize(ByteBufferInput input) {
        int version = input.readInt();
        super.deserialize(input);

        password = input.readString();
        sni = input.readString();
        type = input.readString();
        //noinspection SwitchStatementWithTooFewBranches
        switch (type) {
            case "ws": {
                host = input.readString();
                path = input.readString();
                break;
            }
        }
        encryption = input.readString();
        if (version <= 2 && encryption.startsWith("ss;")) {
            String method = encryption.substring("ss;".length(), encryption.indexOf(":") - 1).toLowerCase();
            String pass = encryption.substring(encryption.indexOf(":") + 1);
            encryption = "ss;" + method + ":" + pass;
        }
        if (version <= 4) {
            input.readString(); // plugin, removed
        }
        if (version >= 1) {
            allowInsecure = input.readBoolean();
        }
        if (version >= 2) {
            utlsFingerprint = input.readString();
        }
        if (version >= 4) {
            mux = input.readBoolean();
            muxConcurrency = input.readInt();
        }
    }

    @Override
    public void applyFeatureSettings(AbstractBean other) {
        if (!(other instanceof TrojanGoBean bean)) return;
        if (allowInsecure) {
            bean.allowInsecure = true;
        }
        bean.mux = mux;
        bean.muxConcurrency = muxConcurrency;
        bean.utlsFingerprint = utlsFingerprint;

    }

    @Override
    public String network() {
        return "tcp";
    }

    @NotNull
    @Override
    public TrojanGoBean clone() {
        return KryoConverters.deserialize(new TrojanGoBean(), KryoConverters.serialize(this));
    }

    public static final Creator<TrojanGoBean> CREATOR = new CREATOR<TrojanGoBean>() {
        @NonNull
        @Override
        public TrojanGoBean newInstance() {
            return new TrojanGoBean();
        }

        @Override
        public TrojanGoBean[] newArray(int size) {
            return new TrojanGoBean[size];
        }
    };
}
