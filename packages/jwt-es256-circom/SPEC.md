# ZK-ID Circuit Specification

## Overview

This document describes the circuits used for privacy-preserving identity verification using zero-knowledge proofs (ZKPs). These circuits enable verification of JWT claims without revealing sensitive personal data.

### List of Circuits

- `jwt` - JWT signature verification circuit

- `claim-decoder` - Claims decoding circuit

- `utils` - Selective disclosure claims decoding and birthday extraction circuit

- `age_verifier` - Age verification circuit

- `es256` - ES256 (ECDSA) signature verification circuit

---

## JWT Circuit Parameters

| Parameter             | Description                                                |
| --------------------- | ---------------------------------------------------------- |
| `n, k`                | Parameters defining ES256 signature size and field chunks. |
| `maxMessageLength`    | Maximum length of JWT message (header + payload).          |
| `maxB64HeaderLength`  | Maximum Base64-encoded JWT header length.                  |
| `maxB64PayloadLength` | Maximum Base64-encoded JWT payload length.                 |
| `maxMatches`          | Maximum number of claims/substrings to check.              |
| `maxSubstringLength`  | Maximum length for substring matches.                      |
| `maxClaimsLength`     | Maximum length for individual claims.                      |

---

## JWT Circuit Inputs

| Input            | Description                                              |
| ---------------- | -------------------------------------------------------- |
| `message`        | JWT message containing header and payload                |
| `messageLength`  | Length of the JWT message                                |
| `periodIndex`    | Index of the period separating header and payload in JWT |
| `sig_r`, `sig_s` | Components of JWT ES256 signature                        |
| `pubkey`         | Public key used for JWT signature verification           |
| `matchesCount`   | Number of substring matches provided                     |
| `matchSubstring` | Array of substrings (hashed claims)                      |
| `matchLength`    | Length of each substring                                 |
| `matchIndex`     | Starting index of each substring within the payload      |
| `claims`         | Array of raw Base64-encoded claims                       |
| `claimLengths`   | Length of each claim                                     |
| `currentYear`    | Current year for age verification                        |
| `currentMonth`   | Current month for age verification                       |
| `currentDay`     | Current day for age verification                         |

---

## JWT Circuit Outputs

| Output       | Description                                                  |
| ------------ | ------------------------------------------------------------ |
| `ageAbove18` | Boolean indicating whether age extracted from claims is ≥ 18 |

---

## Constraints

1.  **ES256 Signature Verification**

    - Validate the ECDSA signature (ES256) of the JWT header and payload using the provided public key.

    - Hash the JWT payload using SHA-256.

2.  **ClaimDecoder**

    - Decode JWT claims from Base64 format.

    - Hash decoded raw claims using SHA-256.

3.  **ClaimComparator**

    - Compute hashes of decoded raw claims.

    - Decode existing hashed claims from selective disclosure inputs.

    - Ensure claims with non-zero length (`claimLengths[i] > 0`) match the provided hashed claims.

4.  **HeaderPayloadExtractor**

    - Decode JWT header from Base64.

    - Decode JWT payload from Base64.

5.  **SubString Inclusion Check**

    - Verify if hashed claims (`matchSubstring`) match values in `_sd[]` in the decoded JWT payload.

6.  **Age Claim Decoding**

    - Decode the second claim, assumed always to be the age claim, from Base64.

    - Extract the YYMMDD birth date and verify whether the age is above 18.

---

## Workflow

1.  **JWT Signature Verification:** Validate JWT signature and hash payload.

2.  **Claims Decoding:** Decode claims from JWT payload and hash them.

3.  **Claims Matching:** Compare decoded and hashed claims against selective disclosure data.

4.  **Age Verification:** Extract and verify user's age from decoded birth date claim.
