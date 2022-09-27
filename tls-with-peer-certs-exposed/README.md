# tls-with-peer-certs-exposed

## 快速开始

### 1. 启动服务器
```bash
cargo run
```

### 2. 发送请求
```bash
cargo run --bin client
```

客户端的样例输出如下
```bash
verifying server's cert ...
Body:
tkms testbot
```

服务端的样例输出如下
```bash
Starting to serve on https://127.0.0.1:1337.
verifying client cert ...
#(peer certs) = 1
certs[0] goes as
-----BEGIN CERTIFICATE-----
MIIBpTCCAUugAwIBAgIUcAI+HkQFYAPhvtTKMlN16q2OlbgwCgYIKoZIzj0EAwIw
IDELMAkGA1UEBhMCQ04xETAPBgNVBAgMCFNoZW5aaGVuMB4XDTIyMDkyNzAzMjIx
MFoXDTIzMDkyODAzMjIxMFowIDELMAkGA1UEBhMCQ04xETAPBgNVBAgMCFNoZW5a
aGVuMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEhO+JF+qIFtVoXubGFB+939tV
MfIBXWHnKCtizYVD02TSI14XpBhJoVPjhLfHy/QBUqpLJcM1BogEyrlEcEaGkqNj
MGEwHQYDVR0OBBYEFHOeHYRk52e/znT+wWaySlBlgco1MB8GA1UdIwQYMBaAFHOe
HYRk52e/znT+wWaySlBlgco1MA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQD
AgGGMAoGCCqGSM49BAMCA0gAMEUCIQD62ptcuXT2RkPx0ORbenC5cDux31KB2Ypn
2nsyStJtQQIgRMl+yOQDDSCYdB9uA6NT93eMug8PYl+4YeV0i7CNa4E=
-----END CERTIFICATE-----
```

其中 `certs[0]` 等于 static/pki/client.crt。

## 参考文献
- [hyper-rustls-examples](https://github.com/rustls/hyper-rustls/tree/c64ea2103a282992a6b0373f0e944e1c8ef4f988/examples)
- [hyper-issues#2463](https://github.com/hyperium/hyper/issues/2463#issuecomment-797093481)
- [hyper/server/mod.rs#L118](https://github.com/hyperium/hyper/blob/v0.14.20/src/server/mod.rs#L118)
