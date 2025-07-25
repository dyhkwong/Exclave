package io.nekohasekai.sagernet.fmt.shadowquic;

import androidx.annotation.NonNull;

import com.esotericsoftware.kryo.io.ByteBufferInput;
import com.esotericsoftware.kryo.io.ByteBufferOutput;

import io.nekohasekai.sagernet.fmt.AbstractBean;
import io.nekohasekai.sagernet.fmt.KryoConverters;

public class ShadowQUICBean extends AbstractBean {

    public String username;
    public String password;
    public String sni;
    public String alpn;
    public String congestionControl;
    public Boolean zeroRTT;
    public Boolean udpOverStream;

    @Override
    public void initializeDefaultValues() {
        super.initializeDefaultValues();
        if (username == null) username = "";
        if (password == null) password = "";
        if (sni == null) sni = "";
        if (alpn == null) alpn = "";
        if (congestionControl == null) congestionControl = "bbr";
        if (zeroRTT == null) zeroRTT = false;
        if (udpOverStream == null) udpOverStream = false;
    }

    @Override
    public void serialize(ByteBufferOutput output) {
        super.serialize(output);
        output.writeInt(0);
        output.writeString(username);
        output.writeString(password);
        output.writeString(sni);
        output.writeString(alpn);
        output.writeString(congestionControl);
        output.writeBoolean(zeroRTT);
        output.writeBoolean(udpOverStream);
    }

    @Override
    public void deserialize(ByteBufferInput input) {
        super.deserialize(input);
        int version = input.readInt();
        username = input.readString();
        password = input.readString();
        sni = input.readString();
        alpn = input.readString();
        congestionControl = input.readString();
        zeroRTT = input.readBoolean();
        udpOverStream = input.readBoolean();
    }

    @Override
    public String network() {
        return "udp";
    }

    @NonNull
    @Override
    public ShadowQUICBean clone() {
        return KryoConverters.deserialize(new ShadowQUICBean(), KryoConverters.serialize(this));
    }

    public static final Creator<ShadowQUICBean> CREATOR = new CREATOR<>() {
        @NonNull
        @Override
        public ShadowQUICBean newInstance() {
            return new ShadowQUICBean();
        }

        @Override
        public ShadowQUICBean[] newArray(int size) {
            return new ShadowQUICBean[size];
        }
    };


}
