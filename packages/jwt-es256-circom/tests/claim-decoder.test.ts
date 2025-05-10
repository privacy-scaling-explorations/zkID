import { sha256 } from "@noble/hashes/sha2";
import assert from "assert";
import { WitnessTester } from "circomkit";
import { circomkit } from "./common";
import { encodeClaims } from "../src/utils";

describe("ClaimDecoder", () => {
  let circuit: WitnessTester<["claims", "claimLengths"], ["decodedClaims", "claimHashes"]>;

  const maxClaimsLength = 128;
  const maxClaims = 3;

  before(async () => {
    circuit = await circomkit.WitnessTester("ClaimDecoder", {
      file: "claim-decoder",
      template: "ClaimDecoder",
      params: [maxClaims, maxClaimsLength],
      recompile: true,
    });
  });

  it("It should decode raw claims with padding correctly", async () => {
    const inputs = [
      "WyJ1cWJ5Y0VSZlN4RXF1a0dtWGwyXzl3IiwibmFtZSIsImRlbmtlbmkiXQ",
      "WyJYMXllNDloV0s1bTJneWFBLXROQXRnIiwicm9jX2JpcnRoZGF5IiwiMDc1MDEwMSJd",
    ];
    const expectedOutputs = inputs.map(atob);

    const { claimArray, claimLengths } = encodeClaims(inputs, maxClaims, maxClaimsLength);

    const witness = await circuit.calculateWitness({
      claims: claimArray,
      claimLengths,
    });

    const outputs = await circuit.readWitnessSignals(witness, ["decodedClaims", "claimHashes"]);

    console.log(outputs.decodedClaims);
    const decodedClaims = outputs.decodedClaims as number[][];
    const circuitClaimHash = outputs.claimHashes as number[][];

    for (let i = 0; i < inputs.length; i++) {
      const length = Number(claimLengths[i]);
      const base64 = decodedClaims[i]
        .slice(0, length)
        .map((c) => String.fromCharCode(Number(c)))
        .join("")
        .replace(/[\x00-\x1F]+$/g, "");

      assert.strictEqual(base64, expectedOutputs[i]);

      const expectedHash = sha256(Uint8Array.from(Buffer.from(inputs[i].slice(0, length), "utf8")));
      const expectedHashHex = Array.from(expectedHash, (b) => b.toString(16).padStart(2, "0")).join("");
      const circuitHashHex = circuitClaimHash[i].map((b) => b.toString(16).padStart(2, "0")).join("");

      assert.strictEqual(circuitHashHex, expectedHashHex);
    }
    await circuit.expectConstraintPass(witness);
  });
});
