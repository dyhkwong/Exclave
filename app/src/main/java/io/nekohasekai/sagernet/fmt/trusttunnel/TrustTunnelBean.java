/******************************************************************************
 *                                                                            *
 * Copyright (C) 2026  dyhkwong                                               *
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
 * along with this program. If not, see <https://www.gnu.org/licenses/>.      *
 *                                                                            *
 ******************************************************************************/

package io.nekohasekai.sagernet.fmt.trusttunnel;

import androidx.annotation.NonNull;

import com.esotericsoftware.kryo.io.ByteBufferInput;
import com.esotericsoftware.kryo.io.ByteBufferOutput;

import org.jetbrains.annotations.NotNull;

import io.nekohasekai.sagernet.fmt.AbstractBean;
import io.nekohasekai.sagernet.fmt.KryoConverters;
import libcore.Libcore;

public class TrustTunnelBean extends AbstractBean {

    public String protocol;
    public String username;
    public String password;
    public String sni;
    public String certificate;
    public String utlsFingerprint;
    public Boolean allowInsecure;

    @Override
    public void initializeDefaultValues() {
        super.initializeDefaultValues();
        if (protocol == null) protocol = "https";
        if (username == null) username = "";
        if (password == null) password = "";
        if (sni == null) sni = "";
        if (certificate == null) certificate = "";
        if (utlsFingerprint == null) utlsFingerprint = "";
        if (allowInsecure == null) allowInsecure = false;
    }

    @Override
    public void serialize(ByteBufferOutput output) {
        output.writeInt(1);
        super.serialize(output);
        output.writeString(protocol);
        output.writeString(username);
        output.writeString(password);
        output.writeString(sni);
        output.writeString(certificate);
        output.writeString(utlsFingerprint);
        output.writeBoolean(allowInsecure);
    }

    @Override
    public void deserialize(ByteBufferInput input) {
        int version = input.readInt();
        super.deserialize(input);
        protocol = input.readString();
        username = input.readString();
        password = input.readString();
        sni = input.readString();
        certificate = input.readString();
        utlsFingerprint = input.readString();
        if (version >= 1) {
            allowInsecure = input.readBoolean();
        }
    }

    @Override
    public void applyFeatureSettings(AbstractBean other) {
        if (!(other instanceof TrustTunnelBean bean)) return;
        if (allowInsecure) {
            bean.allowInsecure = true;
        }
        if (bean.certificate == null || bean.certificate.isEmpty() && !certificate.isEmpty()) {
            bean.certificate = certificate;
        }
        bean.utlsFingerprint = utlsFingerprint;
    }

    @NotNull
    @Override
    public TrustTunnelBean clone() {
        return KryoConverters.deserialize(new TrustTunnelBean(), KryoConverters.serialize(this));
    }

    public static final Creator<TrustTunnelBean> CREATOR = new CREATOR<>() {
        @NonNull
        @Override
        public TrustTunnelBean newInstance() {
            return new TrustTunnelBean();
        }

        @Override
        public TrustTunnelBean[] newArray(int size) {
            return new TrustTunnelBean[size];
        }
    };

    @Override
    public boolean isInsecure() {
        if (Libcore.isLoopbackIP(serverAddress) || serverAddress.equals("localhost")) {
            return false;
        }
        if (!allowInsecure) {
            return false;
        }
        return true;
    }
}
