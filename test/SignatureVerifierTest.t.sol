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

    function testVerifySignatureEIP712() public {
        uint256 message = 24;
        (uint8 v, bytes32 r, bytes32 s) = _signMessageEIP712(message);

        bool verified = signatureVerifier.verifySignerEIP712(
            message,
            v,
            r,
            s,
            user.addr
        );

        assertEq(verified, true);
    }

    // sig replay attack
    function testSignatureCanBeReplayed() public {
        uint256 message = 25;
        // Sign a message
        (uint8 v, bytes32 r, bytes32 s) = _signMessageEIP712(message);

        // verify the message

        vm.prank(address(1));
        bool verifiedOnce = signatureVerifier.verifySignerEIP712(
            message,
            v,
            r,
            s,
            user.addr
        );
        console2.log("verifiedOnce result ", verifiedOnce);
        console2.log("user1 addr ", user.addr);

        vm.prank(address(2));
        bool verifiedTwice = signatureVerifier.verifySignerEIP712(
            message,
            v,
            r,
            s,
            user.addr
        );
        console2.log("verifiedTwice result ", verifiedTwice);
        console2.log("user2 addr ", user.addr);

        assertEq(verifiedOnce, true);
        assertEq(verifiedTwice, true);
        assertEq(verifiedOnce, verifiedTwice);
    }

    // replay resistant

    function testVerifySignatureReplayResistant() public {
        uint256 message = 26;

        // Sign a message
        (uint8 v, bytes32 r, bytes32 s) = _signMessageReplayResistant(message);

        SignatureVerifier.ReplayResistantMessage
            memory messageStruct = getReplayResistantMessageStruct(message);

        // Verify message
        vm.prank(address(1));
        bool verifiedOnce = signatureVerifier.verifySignerReplayResistant(
            messageStruct,
            v,
            r,
            s,
            user.addr
        );
        console2.log("verifiedOnce result ", verifiedOnce);
        assertEq(verifiedOnce, true);

        vm.prank(address(2));
        vm.expectRevert();
        signatureVerifier.verifySignerReplayResistant(
            messageStruct,
            v,
            r,
            s,
            user.addr
        );
    }

    function testIncorrectSignatureAreNotVerified() public {
        uint256 message = 27;
        // Sign a message
        (uint8 v, bytes32 r, bytes32 s) = _signMessageReplayResistant(message);

        // make message wrong
        if (v == type(uint8).max) {
            v = v - 1;
        } else {
            v = v + 1;
        }
        
        SignatureVerifier.ReplayResistantMessage
            memory messageStruct = getReplayResistantMessageStruct(message);

        // Verify message
        vm.expectRevert();
        bool verifiedOnce = signatureVerifier.verifySignerReplayResistant(
            messageStruct,
            v,
            r,
            s,
            user.addr
        );

        assertEq(verifiedOnce, false);
    }

    // Sign tools

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

    function _signMessageEIP712(
        uint256 message
    ) internal view returns (uint8, bytes32, bytes32) {
        bytes1 prefix = bytes1(0x19);
        bytes1 eip191Version = bytes1(0x01);

        bytes32 hashedMessageStruct = keccak256(
            abi.encode(
                signatureVerifier.MESSAGE_TYPEHASH(),
                SignatureVerifier.Message({number: message})
            )
        );

        bytes32 digest = keccak256(
            abi.encodePacked(
                prefix,
                eip191Version,
                signatureVerifier.i_domain_separator(),
                hashedMessageStruct
            )
        );
        return vm.sign(user.key, digest);
    }

    uint256 public constant DEADLINE_EXTENSION = 100;

    function getReplayResistantMessageStruct(
        uint256 message
    ) public view returns (SignatureVerifier.ReplayResistantMessage memory) {
        uint256 nonce = signatureVerifier.latestNonce(user.addr) + 1;

        return
            SignatureVerifier.ReplayResistantMessage({
                number: message,
                deadline: block.timestamp + DEADLINE_EXTENSION,
                nonce: nonce
            });
    }

    function _signMessageReplayResistant(
        uint256 message
    ) internal view returns (uint8, bytes32, bytes32) {
        SignatureVerifier.ReplayResistantMessage
            memory replayResistantMessage = getReplayResistantMessageStruct(
                message
            );

        bytes1 prefix = bytes1(0x19);
        bytes1 eip712Version = bytes1(0x01);

        bytes32 hashedMessageStruct = keccak256(
            abi.encode(
                signatureVerifier.REPLAY_RESISTANT_MESSAGE_TYPEHASH(),
                replayResistantMessage
            )
        );

        bytes32 digest = keccak256(
            abi.encodePacked(
                prefix,
                eip712Version,
                signatureVerifier.i_domain_separator(),
                hashedMessageStruct
            )
        );
        return vm.sign(user.key, digest);
    }
}
