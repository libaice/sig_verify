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

    // EIP 191

    function getSigner191(
        uint256 message,
        uint8 _v,
        bytes32 _r,
        bytes32 _s
    ) public view returns (address) {
        bytes1 prefix = bytes1(0x19);
        bytes1 eip191Version = bytes1(0);
        address indendedValidatorAddress = address(this);
        bytes32 applicationSpecificData = bytes32(message);

        bytes32 hashedMessage = keccak256(
            abi.encodePacked(
                prefix,
                eip191Version,
                indendedValidatorAddress,
                applicationSpecificData
            )
        );
        address signer = ecrecover(hashedMessage, _v, _r, _s);
        return signer;
    }

    function verifySigner191(
        uint256 message,
        uint8 _v,
        bytes32 _r,
        bytes32 _s,
        address signer
    ) public view returns (bool) {
        address actualSigner = getSigner191(message, _v, _r, _s);
        require(signer == actualSigner, "SignatureVerifier: invalid signature");
        return true;
    }
}
