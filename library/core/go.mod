module libcore

go 1.24.0

require (
	github.com/ccding/go-stun v0.1.5
	github.com/golang/protobuf v1.5.4
	github.com/quic-go/quic-go v0.59.0
	github.com/sagernet/gomobile v0.1.11
	github.com/v2fly/v2ray-core/v5 v5.44.1
	github.com/wzshiming/socks5 v0.7.0
	golang.org/x/sys v0.41.0
	gvisor.dev/gvisor v0.0.0-20250503011706-39ed1f5ac29c
)

require (
	github.com/adrg/xdg v0.5.3 // indirect
	github.com/aead/chacha20 v0.0.0-20180709150244-8b13a72661da // indirect
	github.com/andybalholm/brotli v1.0.6 // indirect
	github.com/anytls/sing-anytls v0.0.11 // indirect
	github.com/apernet/quic-go v0.57.2-0.20260111184307-eec823306178 // indirect
	github.com/dgryski/go-camellia v0.0.0-20191119043421-69a8a13fb23d // indirect
	github.com/dgryski/go-metro v0.0.0-20200812162917-85c65e2d0165 // indirect
	github.com/dyhkwong/hysteria/core/v2 v2.7.0-1 // indirect
	github.com/dyhkwong/hysteria/extras/v2 v2.7.0-1 // indirect
	github.com/dyhkwong/sing-juicity v0.1.0-beta.6 // indirect
	github.com/enfein/mieru/v3 v3.27.0 // indirect
	github.com/gofrs/uuid/v5 v5.4.0 // indirect
	github.com/golang-collections/go-datastructures v0.0.0-20150211160725-59788d5eb259 // indirect
	github.com/google/btree v1.1.3 // indirect
	github.com/gorilla/websocket v1.5.3 // indirect
	github.com/hashicorp/yamux v0.1.2 // indirect
	github.com/klauspost/compress v1.17.9 // indirect
	github.com/klauspost/cpuid/v2 v2.0.12 // indirect
	github.com/lunixbochs/struc v0.0.0-20200707160740-784aaebc1d40 // indirect
	github.com/metacubex/utls v1.8.4 // indirect
	github.com/miekg/dns v1.1.72 // indirect
	github.com/pion/transport/v4 v4.0.1 // indirect
	github.com/pires/go-proxyproto v0.10.0 // indirect
	github.com/quic-go/qpack v0.6.0 // indirect
	github.com/refraction-networking/utls v1.8.2 // indirect
	github.com/riobard/go-bloom v0.0.0-20200614022211-cdc8013cb5b3 // indirect
	github.com/sagernet/quic-go v0.59.0-sing-box-mod.2 // indirect
	github.com/sagernet/sing v0.8.0-beta.16 // indirect
	github.com/sagernet/sing-mux v0.3.4 // indirect
	github.com/sagernet/sing-quic v0.6.0-beta.12 // indirect
	github.com/sagernet/sing-shadowsocks v0.2.9 // indirect
	github.com/sagernet/sing-shadowsocks2 v0.2.2 // indirect
	github.com/sagernet/sing-shadowtls v0.2.1-0.20250503051639-fcd445d33c11 // indirect
	github.com/sagernet/smux v1.5.50-sing-box-mod.1 // indirect
	github.com/seiflotfy/cuckoofilter v0.0.0-20240715131351-a2f2c23f1771 // indirect
	github.com/v2fly/BrowserBridge v0.0.0-20210430233438-0570fc1d7d08 // indirect
	github.com/v2fly/ss-bloomring v0.0.0-20210312155135-28617310f63e // indirect
	github.com/v2fly/struc v0.0.0-20241227015403-8e8fa1badfd6 // indirect
	github.com/xtaci/smux v1.5.15 // indirect
	go4.org/netipx v0.0.0-20231129151722-fdeea329fbba // indirect
	golang.org/x/crypto v0.47.0 // indirect
	golang.org/x/exp v0.0.0-20250911091902-df9299821621 // indirect
	golang.org/x/mod v0.31.0 // indirect
	golang.org/x/net v0.49.0 // indirect
	golang.org/x/sync v0.19.0 // indirect
	golang.org/x/text v0.33.0 // indirect
	golang.org/x/time v0.12.0 // indirect
	golang.org/x/tools v0.40.0 // indirect
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2 // indirect
	golang.zx2c4.com/wireguard v0.0.0-20250521234502-f333402bd9cb // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20251029180050-ab9386a59fda // indirect
	google.golang.org/grpc v1.78.0 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
	lukechampine.com/blake3 v1.4.1 // indirect
)

// workaround https://github.com/google/gvisor/commit/868dfbce4fd59f03145e2bc5ac0b585917c371fa
replace gvisor.dev/gvisor => gvisor.dev/gvisor v0.0.0-20250429202743-3a608a52255d

//replace github.com/v2fly/v2ray-core/v5 => ../../../v2ray-core

replace github.com/v2fly/v2ray-core/v5 => github.com/dyhkwong/v2ray-core/v5 v5.44.2-0.20260209072745-caa0cab52b33
