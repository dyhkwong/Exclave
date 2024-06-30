package io.nekohasekai.sagernet.fmt.juicity;

import androidx.annotation.NonNull;

import com.esotericsoftware.kryo.io.ByteBufferInput;
import com.esotericsoftware.kryo.io.ByteBufferOutput;

import org.jetbrains.annotations.NotNull;

import io.nekohasekai.sagernet.fmt.AbstractBean;
import io.nekohasekai.sagernet.fmt.KryoConverters;

public class JuicityBean extends AbstractBean {

    public String uuid;
    public String password;
    public String sni;
    public Boolean allowInsecure;
    public String congestionControl; // https://github.com/daeuniverse/softwind/blob/6daa40f6b7a5cb9a0c44ea252e86fcb3440a7a0e/protocol/tuic/common/congestion.go#L15
    public String pinnedCertChainSha256;

    @Override
    public void initializeDefaultValues() {
        super.initializeDefaultValues();
        if (uuid == null) uuid = "";
        if (password == null) password = "";
        if (sni == null) sni = "";
        if (allowInsecure == null) allowInsecure = false;
        if (congestionControl == null) congestionControl = "bbr";
        if (pinnedCertChainSha256 == null) pinnedCertChainSha256 = "";
    }

    @Override
    public void serialize(ByteBufferOutput output) {
        output.writeInt(2);
        super.serialize(output);
        output.writeString(uuid);
        output.writeString(password);
        output.writeString(sni);
        output.writeBoolean(allowInsecure);
        output.writeString(congestionControl);
        output.writeString(pinnedCertChainSha256);
    }

    @Override
    public void deserialize(ByteBufferInput input) {
        int version = input.readInt();
        super.deserialize(input);
        uuid = input.readString();
        password = input.readString();
        sni = input.readString();
        allowInsecure = input.readBoolean();
        congestionControl = input.readString();
        if (version >= 2) {
            pinnedCertChainSha256 = input.readString();
        }
    }

    @Override
    public boolean canTCPing() {
        return false;
    }

    @NotNull
    @Override
    public JuicityBean clone() {
        return KryoConverters.deserialize(new JuicityBean(), KryoConverters.serialize(this));
    }

    public static final Creator<JuicityBean> CREATOR = new CREATOR<>() {
        @NonNull
        @Override
        public JuicityBean newInstance() {
            return new JuicityBean();
        }

        @Override
        public JuicityBean[] newArray(int size) {
            return new JuicityBean[size];
        }
    };
}
