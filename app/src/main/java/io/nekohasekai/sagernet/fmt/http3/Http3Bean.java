/******************************************************************************
 *                                                                            *
 * Copyright (C) 2025 by dyhkwong                                             *
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

package io.nekohasekai.sagernet.fmt.http3;

import androidx.annotation.NonNull;

import com.esotericsoftware.kryo.io.ByteBufferInput;
import com.esotericsoftware.kryo.io.ByteBufferOutput;

import org.jetbrains.annotations.NotNull;

import io.nekohasekai.sagernet.fmt.AbstractBean;
import io.nekohasekai.sagernet.fmt.KryoConverters;

public class Http3Bean extends AbstractBean {

    public String username;
    public String password;
    public String sni;
    public String certificates;
    public String pinnedPeerCertificateChainSha256;
    public Boolean allowInsecure;
    public String echConfig;

    @Override
    public void initializeDefaultValues() {
        super.initializeDefaultValues();
        if (username == null) username = "";
        if (password == null) password = "";
        if (sni == null) sni = "";
        if (certificates == null) certificates = "";
        if (pinnedPeerCertificateChainSha256 == null) pinnedPeerCertificateChainSha256 = "";
        if (allowInsecure == null) allowInsecure = false;
        if (echConfig == null) echConfig = "";
    }

    @Override
    public void serialize(ByteBufferOutput output) {
        output.writeInt(0);
        super.serialize(output);
        output.writeString(username);
        output.writeString(password);
        output.writeString(sni);
        output.writeString(certificates);
        output.writeString(pinnedPeerCertificateChainSha256);
        output.writeBoolean(allowInsecure);
        output.writeString(echConfig);
        output.writeString(""); // echDohServer, removed
    }

    @Override
    public void deserialize(ByteBufferInput input) {
        int version = input.readInt();
        super.deserialize(input);
        username = input.readString();
        password = input.readString();
        sni = input.readString();
        certificates = input.readString();
        pinnedPeerCertificateChainSha256 = input.readString();
        allowInsecure = input.readBoolean();
        echConfig = input.readString();
        input.readString(); // echDohServer, removed
    }

    @Override
    public void applyFeatureSettings(AbstractBean other) {
        if (!(other instanceof Http3Bean bean)) return;
        if (allowInsecure) {
            bean.allowInsecure = true;
        }
        bean.certificates = certificates;
        if (bean.pinnedPeerCertificateChainSha256 == null || bean.pinnedPeerCertificateChainSha256.isEmpty() &&
                !pinnedPeerCertificateChainSha256.isEmpty()) {
            bean.pinnedPeerCertificateChainSha256 = pinnedPeerCertificateChainSha256;
        }
        bean.echConfig = echConfig;
    }

    @NotNull
    @Override
    public Http3Bean clone() {
        return KryoConverters.deserialize(new Http3Bean(), KryoConverters.serialize(this));
    }

    public static final Creator<Http3Bean> CREATOR = new CREATOR<>() {
        @NonNull
        @Override
        public Http3Bean newInstance() {
            return new Http3Bean();
        }

        @Override
        public Http3Bean[] newArray(int size) {
            return new Http3Bean[size];
        }
    };
}
