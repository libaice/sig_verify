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

        bool verified  = signatureVerifier.verifySignerSimple(message, v, r, s, user.addr);
        assertTrue(verified, "SignatureVerifier: invalid signature");
    }

    function _signMessageSimple(
        uint256 message
    ) internal returns (uint8, bytes32, bytes32) {
        bytes32 digest = bytes32(message);
        return vm.sign(user.key, digest);
    }
}
