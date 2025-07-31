## X9.146 Overview

The X9.146 specification defines a certificate format supporting dual signatures and public keys. This implementation introduces an optional TLS 1.3 extension called Certificate Key Selection (CKS), which indicates which signatures are included in the CertificateVerify message.

### Certificate Key Selection (CKS) Options:
- `DEFAULT (0x00)`: Classical Certificate
- `NATIVE (0x01)`: Classical signature only
- `ALTERNATIVE (0x02)`: Post-quantum signature only
- `BOTH (0x03)`: Hybrid signature (classical + post-quantum)

During the handshake:
1. The client includes the CKS extension in its ClientHello message
2. The server evaluates the extension and, if supported, selects a CKS value to include in its ServerHello response

## Demos and Configuration

Four hybrid algorithm combinations are available for demonstration:

1. P-256 + MLDSA44
2. P-384 + MLDSA65
3. P-521 + MLDSA87
4. RSA-3072 + MLDSA44

### Configuration Options:
- Set CKS mode using `CKS_TYPE`
- Configure handshake algorithms using [list of supported algorithms](#) (link to documentation)
- [Additional configuration details...]

## Interoperability Testing

Test file: [TlsX9146InteroptTest.java](tls%2Fsrc%2Ftest%2Fjava%2Forg%2Fbouncycastle%2Ftls%2Ftest%2FTlsX9146InteroptTest.java)

Comprehensive testing was performed across all combinations of:
- BouncyCastle (BC) TLS server/client
- wolfSSL TLS server/client

### Test Setup

#### Prerequisites:
- Generated conventional/post-quantum keys (converted to PEM using OpenSSL)
- Certificate chains created using wolfSSL utilities
- [PEM files location](#) (link to files)

#### Setup Instructions:

1. **wolfSSL Setup**
    - Clone the wolfSSL repository (outside BC directory)
    - Configure wolfSSL with appropriate settings

2. **Certificate Generation**
    - Clone wolfssl-example repository
    - Run `make scripts`
    - For desired demo: generate certificate chain → perform DER conversion
    - Move PEM files to BC directory

3. **Test Configuration**
    - Set BC parameters in test file:
        - set `wolfSSLWorkingDirectory` to where wolfssl was installed
        - set `DEMO` to wanted test demo
        - set `CKS_TYPE` to wanted Certificate Key Selection Type
        - (Optional) Handshake algorithm

4. **Running Tests**
    - Expected outcome: Successful handshake with no errors
    - **BC Client ↔ wolfSSL Server**
        1. run testOneShotBCClientWithWolfServer()
      
      *OR*
        1. Start wolfSSL server (with correct PEM file paths)
        2. Execute `testWithWolfSSLServer()`
    - **wolfSSL Client ↔ BC Server**
        1. run testOneShotWolfClientWithBCServer()
    
      *OR*
        1. Execute `testRunBCServer()`
        2. Start wolfSSL client (with correct PEM file paths)

## Performance Metrics

### Test Environment:
- **Processor:** Intel Core i7-9750H (6 cores @ 2.60GHz)
- **OS:** Pop!_OS 22.04 LTS
- **Kernel:** Linux 6.9.3
- **Architecture:** x86_64
- **Memory:** 32GB

### Performance Analysis:
- **Summary:** TODO

