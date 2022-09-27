# tls-with-peer-certs-exposed

## 快速开始

### 1. 启动服务器
```bash
cargo run
```

### 2. 使用 ssldump 监听报文

```bash
ssldump -i lo port 1337
```

### 3. 持有自签名证书的客户端发送请求
```bash
cargo run --bin client_with_cert
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

ssldump 的样例输出

```bash
New TCP connection #1: localhost(51756) <-> localhost(1337)
1 1  0.0004 (0.0004)  C>S  Handshake
      ClientHello
        Version 3.3 
        resume [32]=
          fd d7 77 a6 8b 1c 8a ff d5 0f 4e 4e 9a 55 05 af 
          62 90 f4 cb 7e d1 36 48 c0 0d d5 cd 7f 84 e2 7f 
        cipher suites
        TLS_AES_256_GCM_SHA384
        TLS_AES_128_GCM_SHA256
        TLS_CHACHA20_POLY1305_SHA256
        TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
        TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
        TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
        TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
        TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
        TLS_EMPTY_RENEGOTIATION_INFO_SCSV
        compression methods
                  NULL
        extensions
          supported_versions
          ec_point_formats
          supported_groups
          signature_algorithms
          extended_master_secret
          status_request
          server_name
              host_name: localhost
          signed_certificate_timestamp
          key_share
          psk_key_exchange_modes
          session_ticket
1 2  0.0016 (0.0012)  S>C  Handshake
      ServerHello
        Version 3.3 
        session_id[32]=
          fd d7 77 a6 8b 1c 8a ff d5 0f 4e 4e 9a 55 05 af 
          62 90 f4 cb 7e d1 36 48 c0 0d d5 cd 7f 84 e2 7f 
        cipherSuite         TLS_AES_256_GCM_SHA384
        compressionMethod                   NULL
        extensions
          key_share
          supported_versions
1 3  0.0016 (0.0000)  S>C  ChangeCipherSpec
1 4  0.0016 (0.0000)  S>C  application_data
1 5  0.0016 (0.0000)  S>C  application_data
1 6  0.0016 (0.0000)  S>C  application_data
1 7  0.0016 (0.0000)  S>C  application_data
1 8  0.0016 (0.0000)  S>C  application_data
1 9  0.0027 (0.0010)  C>S  ChangeCipherSpec
1 10 0.0027 (0.0000)  C>S  application_data
1 11 0.0027 (0.0000)  C>S  application_data
1 12 0.0027 (0.0000)  C>S  application_data
1 13 0.0031 (0.0004)  C>S  application_data
1 14 0.0032 (0.0000)  S>C  application_data
1 15 0.0035 (0.0002)  S>C  application_data
1 16 0.0039 (0.0003)  C>S  application_data
1    0.0039 (0.0000)  C>S  TCP FIN
1 17 0.0040 (0.0001)  S>C  application_data
```
### 3. 无证书的客户端发送请求
```bash
cargo run --bin client_without_cert
```

客户端日志样例输出如下
```bash
verifying server's cert ...
Body:
tkms testbot without cert
```

服务端日志样例输出如下
```bash
#(peer certs) = 0
```

ssldump 日志样例输出如下

```bash
New TCP connection #2: localhost(51778) <-> localhost(1337)
2 1  0.0004 (0.0004)  C>S  Handshake
      ClientHello
        Version 3.3 
        resume [32]=
          14 f8 10 99 30 dc 20 c0 7f 52 71 c9 2d 37 65 ca 
          76 ea 74 78 9a 08 99 c5 ec e3 34 b9 8f d8 f6 4f 
        cipher suites
        TLS_AES_256_GCM_SHA384
        TLS_AES_128_GCM_SHA256
        TLS_CHACHA20_POLY1305_SHA256
        TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
        TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
        TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
        TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
        TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
        TLS_EMPTY_RENEGOTIATION_INFO_SCSV
        compression methods
                  NULL
        extensions
          supported_versions
          ec_point_formats
          supported_groups
          signature_algorithms
          extended_master_secret
          status_request
          server_name
              host_name: localhost
          signed_certificate_timestamp
          key_share
          psk_key_exchange_modes
          session_ticket
2 2  0.0017 (0.0013)  S>C  Handshake
      ServerHello
        Version 3.3 
        session_id[32]=
          14 f8 10 99 30 dc 20 c0 7f 52 71 c9 2d 37 65 ca 
          76 ea 74 78 9a 08 99 c5 ec e3 34 b9 8f d8 f6 4f 
        cipherSuite         TLS_AES_256_GCM_SHA384
        compressionMethod                   NULL
        extensions
          key_share
          supported_versions
2 3  0.0017 (0.0000)  S>C  ChangeCipherSpec
2 4  0.0017 (0.0000)  S>C  application_data
2 5  0.0017 (0.0000)  S>C  application_data
2 6  0.0017 (0.0000)  S>C  application_data
2 7  0.0017 (0.0000)  S>C  application_data
2 8  0.0017 (0.0000)  S>C  application_data
2 9  0.0027 (0.0010)  C>S  ChangeCipherSpec
2 10 0.0027 (0.0000)  C>S  application_data
2 11 0.0027 (0.0000)  C>S  application_data
2 12 0.0030 (0.0002)  S>C  application_data
2 13 0.0032 (0.0002)  C>S  application_data
2 14 0.0035 (0.0002)  S>C  application_data
2 15 0.0038 (0.0003)  C>S  application_data
2    0.0038 (0.0000)  C>S  TCP FIN
2 16 0.0041 (0.0003)  S>C  application_data
```


## 参考文献
- [hyper-rustls-examples](https://github.com/rustls/hyper-rustls/tree/c64ea2103a282992a6b0373f0e944e1c8ef4f988/examples)
- [hyper-issues#2463](https://github.com/hyperium/hyper/issues/2463#issuecomment-797093481)
- [hyper/server/mod.rs#L118](https://github.com/hyperium/hyper/blob/v0.14.20/src/server/mod.rs#L118)
- [rustls#AllowAnyAnonymousOrAuthenticatedClient](https://docs.rs/rustls/0.20.6/rustls/server/struct.AllowAnyAnonymousOrAuthenticatedClient.html)
