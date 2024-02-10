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

    struct EIP712Domain {
        string name;
        string version;
        uint256 chainId;
        address verifyingContract;
    }

    bytes32 constant EIP712DOMAIN_TYPEHASH =
        keccak256(
            "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
        );

    EIP712Domain eip_712_domain_separator_struct;
    bytes32 public immutable i_domain_separator;

    constructor() {
        eip_712_domain_separator_struct = EIP712Domain({
            name: "SignatureVerifier",
            version: "1",
            chainId: block.chainid,
            verifyingContract: address(this)
        });

        i_domain_separator = keccak256(
            abi.encode(
                EIP712DOMAIN_TYPEHASH,
                keccak256(bytes(eip_712_domain_separator_struct.name)),
                keccak256(bytes(eip_712_domain_separator_struct.version)),
                eip_712_domain_separator_struct.chainId,
                eip_712_domain_separator_struct.verifyingContract
            )
        );
    }

    struct Message {
        uint256 number;
    }

    bytes32 constant MESSAGE_TYPEHASH = keccak256("Message(uint256 message)");

    function getSignerEIP712(
        uint256 message,
        uint8 _v,
        bytes32 _r,
        bytes32 _s
    ) public view returns (address) {
        bytes1 prefix = bytes1(0x19);
        bytes1 eip712Version = bytes1(0x01);
        bytes32 hashStructOfDomainSeparator = i_domain_separator;

        bytes32 hashedMessage = keccak256(
            abi.encode(MESSAGE_TYPEHASH, Message({number: message}))
        );

        bytes32 digest = keccak256(
            abi.encodePacked(
                prefix,
                eip712Version,
                hashStructOfDomainSeparator,
                hashedMessage
            )
        );
        return ecrecover(digest, _v, _r, _s);
    }

    function verifySignerEIP712(
        uint256 message,
        uint8 _v,
        bytes32 _r,
        bytes32 _s,
        address signer
    ) public view returns (bool) {
        address actualSigner = getSignerEIP712(message, _v, _r, _s);
        require(signer == actualSigner);
        return true;
    }
}
