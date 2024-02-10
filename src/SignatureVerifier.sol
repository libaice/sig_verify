// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

contract SignatureVerifier {
    function getSignerSimple(
        uint256 message,
        uint8 _v,
        bytes32 _r,
        bytes32 _s
    ) public pure returns (address) {
        bytes32 hashedMessage = bytes32(message);
        address signer = ecrecover(hashedMessage, _v, _r, _s);
        return signer;
    }

    function verifySignerSimple(
        uint256 message,
        uint8 _v,
        bytes32 _r,
        bytes32 _s,
        address signer
    ) public pure returns (bool) {
        address actualSigner = getSignerSimple(message, _v, _r, _s);
        require(signer == actualSigner, "SignatureVerifier: invalid signature");
        return true;
    }
}
