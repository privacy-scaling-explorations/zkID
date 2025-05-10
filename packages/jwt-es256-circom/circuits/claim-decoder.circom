pragma circom 2.1.6;
include "jwt_tx_builder/array.circom";
include "@zk-email/circuits/lib/base64.circom";
include "@zk-email/circuits/lib/sha.circom";

/// @title ClaimDecoder
/// @notice Decodes multiple Base64 input claims that might be padded with zeros
/// @param maxClaims: the maximum number of claims to process
/// @param maxClaimsLength: the maximum number of characters in each Base64 input array
/// @input claims: array of raw Base64 input arrays, each padded with zeros
/// @input claimLengths: array containing the actual length of each Base64 claim
/// @output decodedClaims: array of decoded outputs
template ClaimDecoder(maxClaims, maxClaimsLength) {
    var decodedLen = (maxClaimsLength * 3) / 4;

    signal input claims[maxClaims][maxClaimsLength];  
    signal input claimLengths[maxClaims];      

    signal output decodedClaims[maxClaims][decodedLen];

    component paddedClaims[maxClaims];
    component claimDecoders[maxClaims];

    for (var i = 0; i < maxClaims; i++) {
        paddedClaims[i] = SelectSubArrayBase64(maxClaimsLength,maxClaimsLength);
        paddedClaims[i].in <== claims[i];
        paddedClaims[i].startIndex <== 0;
        paddedClaims[i].length <== claimLengths[i];

        claimDecoders[i] = Base64Decode(decodedLen);
        claimDecoders[i].in <== paddedClaims[i].out;

        for (var j = 0; j < decodedLen; j++) {
            decodedClaims[i][j] <== claimDecoders[i].out[j];
        }
    }

    component claimHasher[maxClaims];
    component hashByteConvert[maxClaims][32];
    signal output claimHashes[maxClaims][32]; 

    for (var i = 0; i < maxClaims; i++) {
        claimHasher[i] = Sha256Bytes(maxClaimsLength);
        claimHasher[i].paddedIn <== claims[i];
        claimHasher[i].paddedInLength <== maxClaimsLength;

         for (var j = 0; j < 32; j++) {
            hashByteConvert[i][j] = Bits2Num(8);
            for (var k = 0; k < 8; k++) {
                    hashByteConvert[i][j].in[7-k] <== claimHasher[i].out[j * 8 + k];
                 }
        claimHashes[i][j] <== hashByteConvert[i][j].out;
        }
    }
}   