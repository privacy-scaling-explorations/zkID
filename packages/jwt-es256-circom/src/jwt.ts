import { strict as assert } from "assert";
import { Es256CircuitParams, generateES256Inputs, JwkEcdsaPublicKey, PemPublicKey } from "./es256";
import { encodeClaims, stringToPaddedBigIntArray } from "./utils.ts";

// The JWT Circuit Parameters
interface JwtCircuitParams {
  es256: Es256CircuitParams;
  maxB64HeaderLength: number;
  maxB64PayloadLength: number;
  maxMatches: number;
  maxSubstringLength: number;
  maxClaimLength: number;
}

// Generate JWT Circuit Parameters
export function generateJwtCircuitParams(params: number[]): JwtCircuitParams {
  return {
    es256: {
      n: params[0],
      k: params[1],
      maxMessageLength: params[2],
    },
    maxB64HeaderLength: params[3],
    maxB64PayloadLength: params[4],
    maxMatches: params[5],
    maxSubstringLength: params[6],
    maxClaimLength: params[7],
  };
}

// Generate JWT circuit inputs
export function generateJwtInputs(
  params: JwtCircuitParams,
  token: string,
  pk: JwkEcdsaPublicKey | PemPublicKey,
  matches: string[],
  claims: string[]
) {
  // we are not checking the JWT token format, assuming that is correct
  const [b64header, b64payload, b64signature] = token.split(".");

  // check that we are not exceeding the limits
  assert.ok(b64header.length <= params.maxB64HeaderLength);
  assert.ok(b64payload.length <= params.maxB64PayloadLength);
  assert.ok(matches.length <= params.maxMatches);

  // generate inputs for the ES256 validation
  let es256Inputs = generateES256Inputs(params.es256, `${b64header}.${b64payload}`, b64signature, pk);

  const payload = atob(b64payload);

  let matchSubstring: bigint[][] = [];
  let matchLength: number[] = [];
  let matchIndex: number[] = [];
  for (const match of matches) {
    assert.ok(matches.length <= params.maxSubstringLength);
    const index = payload.indexOf(match);
    assert.ok(index != -1);
    matchSubstring.push(stringToPaddedBigIntArray(match, params.maxSubstringLength));
    matchLength.push(match.length);
    matchIndex.push(index);
  }

  while (matchIndex.length < params.maxMatches) {
    matchSubstring.push(stringToPaddedBigIntArray("", params.maxSubstringLength));
    matchLength.push(0);
    matchIndex.push(0);
  }

  let ageClaim = atob(claims[1]).split(",")[1].replace(/"/g, "").trim();
  assert.ok(ageClaim === "roc_birthday");

  let { claimArray, claimLengths } = encodeClaims(claims, params.maxMatches, params.maxClaimLength);

  const now = new Date();
  const currentYear = BigInt(now.getUTCFullYear());
  const currentMonth = BigInt(now.getUTCMonth() + 1);
  const currentDay = BigInt(now.getUTCDate());

  return {
    ...es256Inputs,
    periodIndex: token.indexOf("."),
    matchesCount: matches.length,
    matchSubstring,
    matchLength,
    matchIndex,
    claims: claimArray,
    claimLengths,
    currentYear,
    currentMonth,
    currentDay,
  };
}
