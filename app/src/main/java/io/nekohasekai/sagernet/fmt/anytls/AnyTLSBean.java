package io.nekohasekai.sagernet.fmt.anytls;

import androidx.annotation.NonNull;

import com.esotericsoftware.kryo.io.ByteBufferInput;
import com.esotericsoftware.kryo.io.ByteBufferOutput;

import org.jetbrains.annotations.NotNull;

import io.nekohasekai.sagernet.fmt.AbstractBean;
import io.nekohasekai.sagernet.fmt.KryoConverters;

public class AnyTLSBean extends AbstractBean {

    public String password;
    public String security;
    public String sni;
    public String alpn;
    public String certificates;
    public String pinnedPeerCertificateChainSha256;
    public Boolean allowInsecure;
    public String utlsFingerprint;
    public String echConfig;
    public String echDohServer;
    public String realityPublicKey;
    public String realityShortId;
    public String realityFingerprint;

    @Override
    public void initializeDefaultValues() {
        super.initializeDefaultValues();
        if (password == null) password = "";
        if (security == null) security = "tls";
        if (sni == null) sni = "";
        if (alpn == null) alpn = "";
        if (certificates == null) certificates = "";
        if (pinnedPeerCertificateChainSha256 == null) pinnedPeerCertificateChainSha256 = "";
        if (allowInsecure == null) allowInsecure = false;
        if (utlsFingerprint == null) utlsFingerprint = "";
        if (echConfig == null) echConfig = "";
        if (echDohServer == null) echDohServer = "";
        if (realityPublicKey == null) realityPublicKey = "";
        if (realityShortId == null) realityShortId = "";
        if (realityFingerprint == null) realityFingerprint = "chrome";
    }

    @Override
    public void serialize(ByteBufferOutput output) {
        output.writeInt(0);
        super.serialize(output);
        output.writeString(password);
        output.writeString(security);
        output.writeString(sni);
        output.writeString(alpn);
        output.writeString(certificates);
        output.writeString(pinnedPeerCertificateChainSha256);
        output.writeBoolean(allowInsecure);
        output.writeString(utlsFingerprint);
        output.writeString(echConfig);
        output.writeString(echDohServer);
        output.writeString(realityPublicKey);
        output.writeString(realityShortId);
        output.writeString(realityFingerprint);

    }

    @Override
    public void deserialize(ByteBufferInput input) {
        int version = input.readInt();
        super.deserialize(input);
        password = input.readString();
        security = input.readString();
        sni = input.readString();
        alpn = input.readString();
        certificates = input.readString();
        pinnedPeerCertificateChainSha256 = input.readString();
        allowInsecure = input.readBoolean();
        utlsFingerprint = input.readString();
        echConfig = input.readString();
        echDohServer = input.readString();
        realityPublicKey = input.readString();
        realityShortId = input.readString();
        realityFingerprint = input.readString();
    }

    @Override
    public void applyFeatureSettings(AbstractBean other) {
        if (!(other instanceof AnyTLSBean bean)) return;
        if (allowInsecure) {
            bean.allowInsecure = true;
        }
        bean.certificates = certificates;
        bean.pinnedPeerCertificateChainSha256 = pinnedPeerCertificateChainSha256;
        bean.echConfig = echConfig;
        bean.echDohServer = echDohServer;
        bean.realityFingerprint = realityFingerprint;
    }

    @NotNull
    @Override
    public AnyTLSBean clone() {
        return KryoConverters.deserialize(new AnyTLSBean(), KryoConverters.serialize(this));
    }

    public static final Creator<AnyTLSBean> CREATOR = new CREATOR<>() {
        @NonNull
        @Override
        public AnyTLSBean newInstance() {
            return new AnyTLSBean();
        }

        @Override
        public AnyTLSBean[] newArray(int size) {
            return new AnyTLSBean[size];
        }
    };
}
