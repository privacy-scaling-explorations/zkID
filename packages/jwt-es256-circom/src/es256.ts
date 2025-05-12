import { p256 } from "@noble/curves/p256";
import { sha256Pad } from "@zk-email/helpers";
import { sha256 } from "@noble/hashes/sha256";
import { strict as assert } from "assert";
import { bigintToLimbs, extractXYFromPEM, base64ToBigInt, uint8ArrayToBigIntArray } from "./utils.ts";

// ES256 Circuit Parameters
export interface Es256CircuitParams {
  n: number;
  k: number;
  maxMessageLength: number;
}

// ECDSA Public Key
export interface JwkEcdsaPublicKey {
  kty: string;
  crv: string;
  kid?: string;
  x: string;
  y: string;
}

// PEM Public Key
export interface PemPublicKey {
  pem: string;
}

// Generate ES256 Circuit Parameters
export function generateEs256CircuitParams(params: number[]): Es256CircuitParams {
  return {
    n: params[0],
    k: params[1],
    maxMessageLength: params[2],
  };
}

// Generate inputs for the ES256 circuit
export function generateES256Inputs(
  params: Es256CircuitParams,
  message: string,
  b64Signature: string,
  pk: JwkEcdsaPublicKey | PemPublicKey
) {
  assert.ok(message.length <= params.maxMessageLength);

  // decode signature
  let sig = Buffer.from(b64Signature, "base64url");
  let sig_decoded = p256.Signature.fromCompact(sig.toString("hex"));
  let sig_r = bigintToLimbs(sig_decoded.r, 43, 6);
  let sig_s = bigintToLimbs(sig_decoded.s, 43, 6);

  // decode public key
  let x, y;
  if ("pem" in pk) {
    let pk1 = pk.pem
      .replace("-----BEGIN PUBLIC KEY-----", "")
      .replace("-----END PUBLIC KEY-----", "")
      .replaceAll("\n", "");
    [x, y] = extractXYFromPEM(pk1);
  } else {
    assert.ok(pk.kty == "EC");
    assert.ok(pk.crv == "P-256");
    [x, y] = [base64ToBigInt(pk.x), base64ToBigInt(pk.y)];
  }

  // internal check
  let pubkey = new p256.ProjectivePoint(x, y, 1n);
  let check = p256.verify(sig.toString("hex"), Buffer.from(sha256(message)).toString("hex"), pubkey.toHex());
  assert.ok(check, "internal check of signature failed");

  // generate padded message
  const encoder = new TextEncoder();
  const messageUint8Array = encoder.encode(message);

  let [messagePadded, messagePaddedLen] = sha256Pad(messageUint8Array, params.maxMessageLength);

  // return inputs
  return {
    sig_r: sig_r,
    sig_s: sig_s,
    pubkey: [bigintToLimbs(x, 43, 6), bigintToLimbs(y, 43, 6)],
    message: uint8ArrayToBigIntArray(messagePadded),
    messageLength: messagePaddedLen,
  };
}
