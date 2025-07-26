package io.nekohasekai.sagernet.fmt.anytls;

import androidx.annotation.NonNull;

import com.esotericsoftware.kryo.io.ByteBufferInput;
import com.esotericsoftware.kryo.io.ByteBufferOutput;

import org.jetbrains.annotations.NotNull;

import io.nekohasekai.sagernet.fmt.AbstractBean;
import io.nekohasekai.sagernet.fmt.KryoConverters;

public class AnyTLSBean extends AbstractBean {

    public String password;
    public Integer idleSessionCheckInterval;
    public Integer idleSessionTimeout;
    public Integer minIdleSession;
    public String security;
    public String sni;
    public String alpn;
    public String certificates;
    public String pinnedPeerCertificateChainSha256;
    public Boolean allowInsecure;
    public String utlsFingerprint;
    public String echConfig;
    public String realityPublicKey;
    public String realityShortId;
    public String realityFingerprint;
    public Boolean realityDisableX25519Mlkem768;

    @Override
    public void initializeDefaultValues() {
        super.initializeDefaultValues();
        if (password == null) password = "";
        if (idleSessionCheckInterval == null) idleSessionCheckInterval = 30;
        if (idleSessionTimeout == null) idleSessionTimeout = 30;
        if (minIdleSession == null) minIdleSession = 0;
        if (security == null) security = "tls";
        if (sni == null) sni = "";
        if (alpn == null) alpn = "";
        if (certificates == null) certificates = "";
        if (pinnedPeerCertificateChainSha256 == null) pinnedPeerCertificateChainSha256 = "";
        if (allowInsecure == null) allowInsecure = false;
        if (utlsFingerprint == null) utlsFingerprint = "";
        if (echConfig == null) echConfig = "";
        if (realityPublicKey == null) realityPublicKey = "";
        if (realityShortId == null) realityShortId = "";
        if (realityFingerprint == null) realityFingerprint = "chrome";
        if (realityDisableX25519Mlkem768 == null) realityDisableX25519Mlkem768 = false;
    }

    @Override
    public void serialize(ByteBufferOutput output) {
        output.writeInt(3);
        super.serialize(output);
        output.writeString(password);
        output.writeInt(idleSessionCheckInterval);
        output.writeInt(idleSessionTimeout);
        output.writeInt(minIdleSession);
        output.writeString(security);
        output.writeString(sni);
        output.writeString(alpn);
        output.writeString(certificates);
        output.writeString(pinnedPeerCertificateChainSha256);
        output.writeBoolean(allowInsecure);
        output.writeString(utlsFingerprint);
        output.writeString(echConfig);
        output.writeString(realityPublicKey);
        output.writeString(realityShortId);
        output.writeString(realityFingerprint);
        output.writeBoolean(realityDisableX25519Mlkem768);
    }

    @Override
    public void deserialize(ByteBufferInput input) {
        int version = input.readInt();
        super.deserialize(input);
        password = input.readString();
        if (version >= 2) {
            idleSessionCheckInterval = input.readInt();
            idleSessionTimeout = input.readInt();
            minIdleSession = input.readInt();
        }
        security = input.readString();
        sni = input.readString();
        alpn = input.readString();
        certificates = input.readString();
        pinnedPeerCertificateChainSha256 = input.readString();
        allowInsecure = input.readBoolean();
        utlsFingerprint = input.readString();
        echConfig = input.readString();
        if (version <= 2) {
            input.readString(); // echDohServer, removed
        }
        realityPublicKey = input.readString();
        realityShortId = input.readString();
        realityFingerprint = input.readString();
        if (version >= 1) {
            realityDisableX25519Mlkem768 = input.readBoolean();
        }
        if (version <= 2) {
            input.readBoolean(); // realityReenableChacha20Poly1305, removed
        }
    }

    @Override
    public void applyFeatureSettings(AbstractBean other) {
        if (!(other instanceof AnyTLSBean bean)) return;
        if (allowInsecure) {
            bean.allowInsecure = true;
        }
        bean.certificates = certificates;
        if (bean.pinnedPeerCertificateChainSha256 == null || bean.pinnedPeerCertificateChainSha256.isEmpty() &&
                !pinnedPeerCertificateChainSha256.isEmpty()) {
            bean.pinnedPeerCertificateChainSha256 = pinnedPeerCertificateChainSha256;
        }
        bean.utlsFingerprint = utlsFingerprint;
        bean.echConfig = echConfig;
        bean.realityFingerprint = realityFingerprint;
        bean.realityDisableX25519Mlkem768 = realityDisableX25519Mlkem768;
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
