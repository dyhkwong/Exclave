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

package io.nekohasekai.sagernet.fmt.v2ray;

import com.esotericsoftware.kryo.io.ByteBufferInput;
import com.esotericsoftware.kryo.io.ByteBufferOutput;

import cn.hutool.core.lang.UUID;
import io.nekohasekai.sagernet.fmt.AbstractBean;
import io.nekohasekai.sagernet.ktx.UUIDsKt;

public abstract class StandardV2RayBean extends AbstractBean {

    public String uuid;
    public String encryption;
    public String type;
    public String host;
    public String path;
    public String headerType;
    public String mKcpSeed;
    public String quicSecurity;
    public String quicKey;
    public String security;
    public String sni;
    public String alpn;

    public String grpcServiceName;
    public Integer maxEarlyData;
    public String earlyDataHeaderName;
    public String meekUrl;
    public String splithttpMode;
    public String splithttpExtra;

    public String certificates;
    public String pinnedPeerCertificateChainSha256;
    public String utlsFingerprint;
    public String echConfig;
    public String echDohServer;

    public Boolean wsUseBrowserForwarder;
    public Boolean shUseBrowserForwarder;
    public Boolean allowInsecure;
    public String packetEncoding;

    public String realityPublicKey;
    public String realityShortId;
    public String realityFingerprint;

    public Integer hy2DownMbps;
    public Integer hy2UpMbps;
    public String hy2Password;

    public String mekyaKcpSeed;
    public String mekyaKcpHeaderType;
    public String mekyaUrl;

    public Boolean mux;
    public Integer muxConcurrency;
    public String muxPacketEncoding;

    @Override
    public boolean canMapping() {
        return switch (type) {
            case "ws" -> !wsUseBrowserForwarder;
            case "splithttp" -> !shUseBrowserForwarder;
            // case "quic" -> false; // "quic" is incompatible with chain proxy but this should be a bug.
            default -> true;
        };
    }

    @Override
    public void initializeDefaultValues() {
        super.initializeDefaultValues();

        if (uuid == null) uuid = "";

        if (type == null) type = "tcp";

        if (host == null) host = "";
        if (path == null) path = "";
        if (headerType == null) headerType = "none";
        if (mKcpSeed == null) mKcpSeed = "";
        if (quicSecurity == null) quicSecurity = "none";
        if (quicKey == null) quicKey = "";
        if (meekUrl == null) meekUrl = "";
        if (splithttpMode == null) splithttpMode = "auto";
        if (splithttpExtra == null) splithttpExtra = "";

        if (security == null) security = "none";
        if (sni == null) sni = "";
        if (alpn == null) alpn = "";

        if (grpcServiceName == null) grpcServiceName = "";
        if (maxEarlyData == null) maxEarlyData = 0;
        if (wsUseBrowserForwarder == null) wsUseBrowserForwarder = false;
        if (shUseBrowserForwarder == null) shUseBrowserForwarder = false;
        if (certificates == null) certificates = "";
        if (pinnedPeerCertificateChainSha256 == null) pinnedPeerCertificateChainSha256 = "";
        if (earlyDataHeaderName == null) earlyDataHeaderName = "";
        if (allowInsecure == null) allowInsecure = false;
        if (packetEncoding == null) packetEncoding = "none";
        if (utlsFingerprint == null) utlsFingerprint = "";
        if (echConfig == null) echConfig = "";
        if (echDohServer == null) echDohServer = "";

        if (realityPublicKey == null) realityPublicKey = "";
        if (realityShortId == null) realityShortId = "";
        if (realityFingerprint == null) realityFingerprint = "chrome";

        if (hy2DownMbps == null) hy2DownMbps = 0;
        if (hy2UpMbps == null) hy2UpMbps = 0;
        if (hy2Password == null) hy2Password = "";

        if (mekyaKcpSeed == null) mekyaKcpSeed = "";
        if (mekyaKcpHeaderType == null) mekyaKcpHeaderType = "none";
        if (mekyaUrl == null) mekyaUrl = "";

        if (mux == null) mux = false;
        if (muxConcurrency == null) muxConcurrency = 8;
        if (muxPacketEncoding == null) muxPacketEncoding = "none";

    }

    @Override
    public void serialize(ByteBufferOutput output) {
        output.writeInt(26);
        super.serialize(output);

        output.writeString(uuid);
        output.writeString(encryption);
        output.writeString(type);

        switch (type) {
            case "tcp": {
                output.writeString(headerType);
                output.writeString(host);
                output.writeString(path);
                break;
            }
            case "kcp": {
                output.writeString(headerType);
                output.writeString(mKcpSeed);
                break;
            }
            case "ws": {
                output.writeString(host);
                output.writeString(path);
                output.writeInt(maxEarlyData);
                output.writeBoolean(wsUseBrowserForwarder);
                output.writeString(earlyDataHeaderName);
                break;
            }
            case "http": {
                output.writeString(host);
                output.writeString(path);
                break;
            }
            case "httpupgrade": {
                output.writeString(host);
                output.writeString(path);
                output.writeInt(maxEarlyData);
                output.writeString(earlyDataHeaderName);
                break;
            }
            case "splithttp": {
                output.writeString(host);
                output.writeString(path);
                output.writeBoolean(shUseBrowserForwarder);
                output.writeString(splithttpMode);
                output.writeString(splithttpExtra);
                break;
            }
            case "quic": {
                output.writeString(headerType);
                output.writeString(quicSecurity);
                output.writeString(quicKey);
                break;
            }
            case "grpc": {
                output.writeString(grpcServiceName);
                break;
            }
            case "meek": {
                output.writeString(meekUrl);
                break;
            }
            case "hysteria2": {
                output.writeInt(hy2DownMbps);
                output.writeInt(hy2UpMbps);
                output.writeString(hy2Password);
                break;
            }
            case "mekya": {
                output.writeString(mekyaKcpHeaderType);
                output.writeString(mekyaKcpSeed);
                output.writeString(mekyaUrl);
                break;
            }
        }

        output.writeString(security);

        switch (security) {
            case "tls": {
                output.writeString(sni);
                output.writeString(alpn);
                output.writeString(certificates);
                output.writeString(pinnedPeerCertificateChainSha256);
                output.writeBoolean(allowInsecure);
                output.writeString(utlsFingerprint);
                output.writeString(echConfig);
                output.writeString(echDohServer);
                break;
            }
            case "reality": {
                output.writeString(sni);
                output.writeString(realityPublicKey);
                output.writeString(realityShortId);
                output.writeString(realityFingerprint);
                break;
            }
        }

        if (this instanceof VMessBean) {
            output.writeInt(((VMessBean) this).alterId);
            output.writeBoolean(((VMessBean) this).experimentalAuthenticatedLength);
            output.writeBoolean(((VMessBean) this).experimentalNoTerminationSignal);
        }
        if (this instanceof VLESSBean) {
            output.writeString(((VLESSBean) this).flow);
        }

        output.writeString(packetEncoding);

        output.writeBoolean(mux);
        output.writeInt(muxConcurrency);
        output.writeString(muxPacketEncoding);
    }

    @Override
    public void deserialize(ByteBufferInput input) {
        int version = input.readInt();
        super.deserialize(input);
        uuid = input.readString();
        encryption = input.readString();
        type = input.readString();

        switch (type) {
            case "tcp": {
                headerType = input.readString();
                host = input.readString();
                path = input.readString();
                break;
            }
            case "kcp": {
                headerType = input.readString();
                mKcpSeed = input.readString();
                break;
            }
            case "ws": {
                host = input.readString();
                path = input.readString();
                maxEarlyData = input.readInt();
                wsUseBrowserForwarder = input.readBoolean();
                if (version >= 2) {
                    earlyDataHeaderName = input.readString();
                }
                break;
            }
            case "http": {
                host = input.readString();
                path = input.readString();
                break;
            }
            case "quic": {
                headerType = input.readString();
                quicSecurity = input.readString();
                quicKey = input.readString();
                if (version >= 16) {
                    break;
                }
            }
            case "grpc": {
                grpcServiceName = input.readString();
                if (version >= 8 && version <= 12) {
                    input.readString(); // grpcMode, removed
                }
                if (version >= 16) {
                    break;
                }
            }
            case "meek": {
                if (version >= 10) {
                    meekUrl = input.readString();
                }
                if (version >= 16) {
                    break;
                }
            }
            case "httpupgrade": {
                if (version >= 12) {
                    host = input.readString();
                    path = input.readString();
                }
                if (version >= 25) {
                    maxEarlyData = input.readInt();
                    earlyDataHeaderName = input.readString();
                }
                if (version >= 16) {
                    break;
                }
            }
            case "hysteria2": {
                if (version >= 14) {
                    hy2DownMbps = input.readInt();
                    hy2UpMbps = input.readInt();
                    if (version < 26) {
                        input.readString(); // hy2ObfsPassword, removed
                    }
                }
                if (version >= 15) {
                    hy2Password = input.readString();
                }
                break;
            }
            case "splithttp": {
                if (version >= 18) {
                    host = input.readString();
                    path = input.readString();
                }
                if (version >= 20) {
                    shUseBrowserForwarder = input.readBoolean();
                }
                if (version >= 23) {
                    splithttpMode = input.readString();
                }
                if (version >= 24) {
                    splithttpExtra = input.readString();
                }
                break;
            }
            case "mekya": {
                if (version >= 22) {
                    mekyaKcpHeaderType = input.readString();
                    mekyaKcpSeed = input.readString();
                    mekyaUrl = input.readString();
                }
                break;
            }
        }

        security = input.readString();
        switch (security) {
            case "tls": {
                sni = input.readString();
                alpn = input.readString();
                if (version >= 1) {
                    certificates = input.readString();
                    pinnedPeerCertificateChainSha256 = input.readString();
                }
                if (version >= 3) {
                    allowInsecure = input.readBoolean();
                }
                if (version >= 9) {
                    utlsFingerprint = input.readString();
                }
                if (version >= 21) {
                    echConfig = input.readString();
                    echDohServer = input.readString();
                }
                break;
            }
            case "xtls": { // removed, for compatibility
                if (version <= 8) {
                    security = "tls";
                    sni = input.readString();
                    alpn = input.readString();
                    input.readString(); // flow, removed
                }
                if (version >= 16) {
                    break;
                }
            }
            case "reality": {
                if (version >= 11) {
                    sni = input.readString();
                    realityPublicKey = input.readString();
                    realityShortId = input.readString();
                    if (version < 26) {
                        input.readString(); // realitySpiderX, removed
                    }
                    realityFingerprint = input.readString();
                }
                break;
            }
        }
        if (this instanceof VMessBean && version != 4 && version < 6) {
            ((VMessBean) this).alterId = input.readInt();
        }
        if (this instanceof VMessBean && version >= 4) {
            if (version >= 17) {
                ((VMessBean) this).alterId = input.readInt();
            }
            ((VMessBean) this).experimentalAuthenticatedLength = input.readBoolean();
            ((VMessBean) this).experimentalNoTerminationSignal = input.readBoolean();
        }
        if (this instanceof VLESSBean && version >= 11) {
            ((VLESSBean) this).flow = input.readString();
        }
        if (version >= 7 && version <= 15) {
            switch (input.readInt()) {
                case 0:
                    packetEncoding = "none";
                    break;
                case 1:
                    packetEncoding = "packet";
                    break;
                case 2:
                    packetEncoding = "xudp";
                    break;
            }
        }
        if (version >= 16) {
            packetEncoding = input.readString();
        }
        if (version >= 19) {
            mux = input.readBoolean();
            muxConcurrency = input.readInt();
            muxPacketEncoding = input.readString();
        }
    }

    @Override
    public boolean canTCPing() {
        return !type.equals("kcp") && !type.equals("quic") && !type.equals("hysteria2");
    }

    @Override
    public void applyFeatureSettings(AbstractBean other) {
        if (!(other instanceof StandardV2RayBean bean)) return;
        if (allowInsecure) {
            bean.allowInsecure = true;
        }
        bean.maxEarlyData = maxEarlyData;
        bean.earlyDataHeaderName = earlyDataHeaderName;
        bean.wsUseBrowserForwarder = wsUseBrowserForwarder;
        bean.shUseBrowserForwarder = shUseBrowserForwarder;
        bean.certificates = certificates;
        bean.pinnedPeerCertificateChainSha256 = pinnedPeerCertificateChainSha256;
        bean.packetEncoding = packetEncoding;
        bean.utlsFingerprint = utlsFingerprint;
        bean.echConfig = echConfig;
        bean.echDohServer = echDohServer;
        // bean.realityFingerprint = realityFingerprint; // fuck RPRX's disgusting "fp"
        bean.hy2DownMbps = hy2DownMbps;
        bean.hy2UpMbps = hy2UpMbps;
        bean.mux = mux;
        bean.muxConcurrency = muxConcurrency;
        bean.muxPacketEncoding = muxPacketEncoding;
    }

    public String uuidOrGenerate() {
        try {
            return UUID.fromString(uuid).toString(false);
        } catch (Exception ignored) {
            return UUIDsKt.uuid5(uuid);
        }
    }

}