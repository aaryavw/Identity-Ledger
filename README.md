# Identity-Ledger: Decentralized Identity Validation on Blockchain

IdentiLedger is a security-focused Java application designed to showcase how decentralized architectures can protect consumer privacy. The system simulates a Zero-Knowledge framework where identity credentials are coded into cryptographic signatures and anchored to an immutable ledger for secure, third-party authentication.

## How It Works
1. **Key Generation:** A trusted issuing authority generates an asymmetric cryptographic public/private keypair (`RSA`).
2. **Data Hashing:** User identity records are compiled into raw data strings and converted into unique 256-bit hashes (`SHA-256`), stripping away raw PII (Personally Identifiable Information) values.
3. **Cryptographic Attestation:** The authority uses its Private Key to legally sign the identity fingerprint, creating a verification token that is appended to the ledger.
4. **Zero-Knowledge Verification:** Third-party entities can use the authority's public key to confirm data validity instantly without ever interacting with or storing the user's raw data documents.

## Project Structure
* `IdentityLedger.java`: The main processing engine driving key serialization, block token injection, and cryptographic assertion checking.

## Core Security Concepts Explored
* **Asymmetric Cryptography:** Utilizing dual-key dependency mappings via `java.security.Signature`.
* **Zero PII Exposure:** Anchoring hashes rather than raw text arrays to defend data payloads against ledger breaches.
* **Tamper Rejection:** Proving how 1-bit discrepancies in submitted strings collapse signature calculations during auditing.
