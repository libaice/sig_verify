// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {SignatureVerifier} from "../src/SignatureVerifier.sol";
import {Test, console2} from "forge-std/Test.sol";

contract SignatureVerifierTest is Test {
    SignatureVerifier public signatureVerifier;

    Account user = makeAccount("victim");
    Account attacker = makeAccount("attacker");

    function setUp() public {
        signatureVerifier = new SignatureVerifier();

        console2.log("signatureVerifier", address(signatureVerifier));
        console2.log("user Addr", user.addr);
        console2.log("attacker Addr", attacker.addr);
    }

    function testVerifySignatureSimple() public {
        uint256 message = 22;
        (uint8 v, bytes32 r, bytes32 s) = _signMessageSimple(message);

        bool verified = signatureVerifier.verifySignerSimple(
            message,
            v,
            r,
            s,
            user.addr
        );
        assertEq(verified, true, "SignatureVerifier: invalid signature");
    }

    function testVerifySignatureEIP191() public {
        uint256 message = 23;
        address intendedValidator = address(signatureVerifier);
        (uint8 v, bytes32 r, bytes32 s) = _signMessageEIP191(
            message,
            intendedValidator
        );

        bool verified = signatureVerifier.verifySigner191(
            message,
            v,
            r,
            s,
            user.addr
        );

        assertEq(verified, true);
    }

    function _signMessageSimple(
        uint256 message
    ) internal returns (uint8, bytes32, bytes32) {
        bytes32 digest = bytes32(message);
        return vm.sign(user.key, digest);
    }

    function _signMessageEIP191(
        uint256 message,
        address intendedValidator
    ) internal view returns (uint8, bytes32, bytes32) {
        bytes1 prefix = bytes1(0x19);
        bytes1 eip191Version = bytes1(0x00);

        bytes32 digest = keccak256(
            abi.encodePacked(prefix, eip191Version, intendedValidator, message)
        );

        return vm.sign(user.key, digest);
    }




}
