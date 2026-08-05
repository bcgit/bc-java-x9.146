# X9.146 QTLS test certificate fixtures

Certificate/key fixtures for the ANSI X9.146 QTLS (draft 2026-07-21) Certificate Key Selection
(CKS) tests in `tls/src/test/java/org/bouncycastle/tls/test/` (`TlsX9146ProtocolTest`,
`MockX9146TlsServer`/`Client`, `TlsX9146InteroptTest`).

**Two synchronized copies exist** — the tests actually load these files through
`TestResourceFinder` from `bc-test-data/tls/credentials/x9146` (the sibling `bc-test-data`
checkout), while `bc-java` tracks a mirror under
`tls/src/test/resources/org/bouncycastle/tls/test/x9146`. The generator (below) writes the same
set to both so they cannot drift. If you change one, regenerate both.

## Inventory

### Chimera sets (CKS 1/2/3, PSK hybrids 7/8; also used as classic single-signer credentials for the Standard rows 0/6)

X.509 (2019) dual-key certificates: native key in the SubjectPublicKeyInfo, ML-DSA alternate key
in the `subjectAltPublicKeyInfo` (2.5.29.72) extension, alternate signature in
`altSignatureAlgorithm`/`altSignatureValue` (2.5.29.73/74). Each family is a self-signed Chimera
root CA issuing one server certificate; both the native and alternate signatures of the server
certificate are made by the CA's keys, and the server's own ML-DSA public key sits in the server
certificate's `subjectAltPublicKeyInfo`.

| Family | Native | Alternate | Files |
|---|---|---|---|
| P256-mldsa44 | ECDSA P-256 (SHA256withECDSA) | ML-DSA-44 | `ca-P256-mldsa44-{cert,key,key-pq}.pem`, `server-P256-mldsa44-cert.pem`, `server-P256-key.pem`, `server-mldsa44-key-pq.pem` |
| P384-mldsa65 | ECDSA P-384 (SHA384withECDSA) | ML-DSA-65 | `ca-P384-mldsa65-{cert,key,key-pq}.pem`, `server-P384-mldsa65-cert.pem`, `server-P384-key.pem`, `server-mldsa65-key-pq.pem` |
| P521-mldsa87 | ECDSA P-521 (SHA512withECDSA) | ML-DSA-87 | `ca-P521-mldsa87-{cert,key,key-pq}.pem`, `server-P521-mldsa87-cert.pem`, `server-P521-key.pem`, `server-mldsa87-key-pq.pem` |
| rsa3072-mldsa44 | RSA-3072 (SHA256withRSA) | ML-DSA-44 | `ca-rsa3072-mldsa44-{cert,key,key-pq}.pem`, `server-rsa3072-mldsa44-cert.pem`, `server-rsa3072-key.pem`, `server-mldsa44-rsa-key-pq.pem` |

Note the rsa3072 set has its **own** ML-DSA-44 key (`server-mldsa44-rsa-key-pq.pem`): X9.146
sec. 6.6 forbids reusing key material across certificates (the pre-2026-08 fixture set shared one
ML-DSA-44 key between the P256 and rsa3072 certificates).

### Composite set (CKS 4, PSK hybrid 9)

A classic ECDSA P-256 CA issuing a server certificate whose SubjectPublicKeyInfo is a composite
**ML-DSA-44 + ECDSA-P256-SHA256** key (draft-ietf-lamps-pq-composite-sigs OID, the key behind
TLS codepoint 0x0907 / draft-reddy-tls-composite-mldsa). The certificate signature itself is
plain ECDSA from the CA, so certificate-chain validation needs no composite support — only the
CertificateVerify exercises the composite algorithm.

`ca-composite-mldsa44-p256-{cert,key}.pem`, `server-composite-mldsa44-p256-{cert,key}.pem`
(the server key is the composite private key, PKCS#8).

### Classic set (CKS 0, PSK hybrid 6)

Plain single-algorithm ECDSA P-256 CA + server, no alternate extensions anywhere — a genuinely
Standard certificate for the CKS 0/6 rows.

`ca-P256-classic-{cert,key}.pem`, `server-P256-classic-{cert,key}.pem`

### Related Certificates Pair (CKS 5, PSK hybrids 10/11)

Two self-signed end-entity certificates per RFC 9763: the Main (P-384) carries the
`RelatedCertificate` extension binding the Related (P-256) by SHA-256 digest. The protocol tests
generate their pair **fresh at runtime** (`X9146RelatedPairUtil`); these static PEMs exist for
interop testing against other stacks.

`related-P256-{cert,key}.pem`, `main-P384-{cert,key}.pem`

## Regenerating

The whole set is produced by `org.bouncycastle.tls.test.X9146CertFixtureGenerator` (in the tls
test sources). Keys are newly generated each run, so the set is always replaced coherently —
never mix files from different runs. From the `bc-java` root, with `bc-test-data` checked out as
a sibling:

```
JAVA_HOME=/path/to/jdk25 ./gradlew :tls:compileTestJava
java -cp "tls/build/classes/java/test:tls/build/classes/java/main:core/build/classes/java/main:util/build/classes/java/main:pkix/build/classes/java/main:prov/build/classes/java/main:prov/build/resources/main" \
    org.bouncycastle.tls.test.X9146CertFixtureGenerator
```

With no arguments it writes to both standard locations (skipping one that is absent); pass one
or more directory paths to write elsewhere. Afterwards run the suite to confirm the new set:

```
JAVA_HOME=/path/to/jdk25 BC_JDK25=/path/to/jdk25 ./gradlew :tls:test --tests org.bouncycastle.tls.test.AllTests
```

Validity is ~10 years from generation. Certificates before 2026-08 were generated externally
(OpenSSL/OQS-provider style, `CN=www.YourDomain.com`) and expired 2026-08-13; the generator is
now the source of truth. Subject DNs are
`C=AU, O=The Legion of the Bouncy Castle, OU=X9.146 QTLS test certificates, CN=X9.146 Test ...`.
