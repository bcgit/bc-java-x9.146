/**
 * Engine for XMSS and the XMSS^MT multi-tree variant per RFC 8391 (hash-based stateful
 * signatures), with the SP 800-208 parameter sets. The public classes here are
 * {@link org.bouncycastle.crypto.signers.xmss.XMSSEngine}, the operations the key parameter
 * classes in {@link org.bouncycastle.crypto.params} and the key pair generators in
 * {@link org.bouncycastle.crypto.generators} are built on, and
 * {@link org.bouncycastle.crypto.signers.xmss.BDS} /
 * {@link org.bouncycastle.crypto.signers.xmss.BDSStateMap}, the opaque form of the BDS
 * authentication-path traversal state an XMSS / XMSS^MT private key carries. Everything else -
 * WOTS+, the hash addressing scheme, the keyed hash functions, the tree arithmetic and the
 * signature structures - is package-private. Applications sign and verify through
 * {@link org.bouncycastle.crypto.signers.XMSSSigner} /
 * {@link org.bouncycastle.crypto.signers.XMSSMTSigner}.
 */
package org.bouncycastle.crypto.signers.xmss;
