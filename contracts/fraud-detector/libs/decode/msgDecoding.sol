// SPDX-License-Identifier: Apache2

/*
Max's comment:



*/


pragma solidity ^0.8.17;

import "../rlp/Helper.sol";
import "../../types/message.sol";
import "../../types/events.sol";

library FraudProofDecoderLibrary {
    using RLPReader for bytes;
    using RLPReader for RLPReader.RLPItem;
    
    // Expects 12 RLP items and hashes
    function decodeResponse(bytes memory res) external returns (ResponseMsg memory, bytes32) {
        // Step 1: Parse the RLP encoded data
        RLPReader.RLPItem[] memory items = res.toRlpItem().toList();
        
        // Step 2: Check if the correct number of fields is present in the RLP-encoded message
        require(items.length == 12, "Incorrect number of fields in RLP encoded data");

        ResponseMsg memory response;
        // Decoding string Type
        response.Type = string(items[0].toBytes());
        
        // Decoding ChannelId (which is a bytes32)
        response.ChannelId = bytes32(items[1].toBytes());

        // Decoding Amount (which is uint)
        response.Amount = items[2].toUint();

        response.ReqBodyHash = bytes32(items[3].toBytes());
        // Decoding SignedReqBody (which is bytes)
        response.SignedReqBody = items[4].toBytes();

        // Decoding CurrentBlockHeight (which is uint)
        response.CurrentBlockHeight = items[5].toUint();

        // Decoding ReturnValue (which is bytes)
        response.ReturnValue = items[6].toBytes();

        // Decoding Proof as an array of strings
        RLPReader.RLPItem[] memory proofItems = items[7].toList();
        response.Proof = new bytes[](proofItems.length);
        for (uint256 i = 0; i < proofItems.length; i++) {
            response.Proof[i] = bytes(proofItems[i].toBytes());
        }

        // Decoding TxHash (which is bytes32)
        response.TxHash = bytes32(items[8].toBytes());

        // Decoding TxIdx (which is uint32)
        response.TxIdx = items[9].toBytes();

        // Decoding Signature (which is bytes)
        response.Signature = items[10].toBytes();

        response.TxRootHash = bytes32(items[11].toBytes());

        // Emit the decoded data as an event to verify the correctness
        emit DecodedResponse(
            response.Type,
            response.ChannelId,
            response.Amount,
            response.ReqBodyHash,
            response.SignedReqBody,
            response.CurrentBlockHeight,
            response.ReturnValue,
            response.Proof,
            response.TxHash,
            response.TxIdx,
            response.Signature
        );

        bytes32 resHash = getMessageHash(response.ChannelId, response.Proof, response.TxHash, response.TxIdx, response.SignedReqBody);
        emit msgHash(resHash);

        return (response, resHash);
    }

    function getMessageHash(
        bytes32 ChannelId,
        bytes[] memory Proof,
        bytes32 TxHash,
        bytes memory TxIdx,
        bytes memory SignedReqBody
    ) public returns (bytes32) {
        // emit txHash(TxHash);
        // emit txIdx(TxIdx);
        // emit emitProof(Proof);
        emit reqByte(SignedReqBody);
        bytes memory proofBytes;
        for (uint256 i = 0; i < Proof.length; i++) {
            proofBytes = abi.encodePacked(proofBytes, Proof[i]);
        }
        return keccak256(abi.encodePacked(
            ChannelId,
            SignedReqBody,
            proofBytes,
            TxHash,
            TxIdx
        ));
    }

    // Expects 4 RLP items and hashes
    function decodeRequest(bytes memory serializedReqBody) public returns(RequestBody memory, bytes32) {
        RLPReader.RLPItem[] memory items = serializedReqBody.toRlpItem().toList();
        
        // Step 2: Check if the correct number of fields is present in the RLP-encoded message
        require(items.length == 4, "Incorrect number of fields in RLP encoded data");
        // emit Debug("Number of fields found", items.length); 
        
        RequestBody memory reqBody;

        // ----- NOTE: REMEMBER THE DEFINATION LOCALLY WILL CHANGE THE ITEM LENGTH


        // // Decoding ChannelId (which is a uint32)
        reqBody.ChannelId = bytes32(items[0].toBytes());

        // // emit emitChannelId(reqBody.ChannelId);
        reqBody.Amount = items[1].toUint();
        emit emitAmount(reqBody.Amount);
        
        // // Decoding Proof as an array of strings
        
        reqBody.LocalBlockHash = bytes32(items[2].toBytes());
        emit emitLocalBlockHash(reqBody.LocalBlockHash);

        reqBody.ReqBytes = items[3].toBytes(); 

        emit DecodeRequest(reqBody.ChannelId, reqBody.Amount, reqBody.LocalBlockHash, reqBody.ReqBytes, items.length);

        bytes32 messageHash = getReqMessageHash(reqBody.ChannelId, reqBody.Amount, reqBody.LocalBlockHash, reqBody.ReqBytes);
        emit msgHash(messageHash);
        return (reqBody, messageHash);
    }

    function getReqMessageHash(
        bytes32 ChannelId,
        uint Amount,
        bytes32 LocalBlockHash,
        bytes memory ReqBytes
    ) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(
            ChannelId,
            Amount,
            LocalBlockHash,
            ReqBytes
        ));
    } 

    // Similar to decodeResponse but for state proof
    function decodeResponseSP(bytes memory encodedMsg) public returns (ResponseSPMsg memory, bytes32) {
        // Decode the RLP-encoded data
        RLPReader.RLPItem[] memory items = encodedMsg.toRlpItem().toList();

        // Ensure the correct number of fields
        require(items.length == 11, "Incorrect number of fields in RLP encoded data");

        ResponseSPMsg memory responseSP;

        // Decode fields
        responseSP.Type = string(items[0].toBytes());
        responseSP.ChannelId = bytes32(items[1].toBytes());
        responseSP.Amount = items[2].toUint();
        responseSP.ReqBodyHash = bytes32(items[3].toBytes());
        responseSP.SignedReqBody = items[4].toBytes();
        responseSP.CurrentBlockHeight = items[5].toUint();
        responseSP.ReturnValue = items[6].toBytes();

        // Decode Proof as an array of dynamic byte arrays
        RLPReader.RLPItem[] memory proofItems = items[7].toList();
        responseSP.Proof = new bytes[](proofItems.length);
        for (uint256 i = 0; i < proofItems.length; i++) {
            responseSP.Proof[i] = proofItems[i].toBytes();
        }

        responseSP.Address = items[8].toBytes();
        // responseSP.BlockNr = items[9].toUint();
        responseSP.Signature = items[9].toBytes();
        responseSP.TxRootHash = bytes32(items[10].toBytes());

        emit DecodedResponseSP(
            responseSP.Type,
            responseSP.ChannelId,
            responseSP.Amount,
            responseSP.ReqBodyHash,
            responseSP.SignedReqBody,
            responseSP.CurrentBlockHeight,
            responseSP.ReturnValue,
            responseSP.Proof,
            responseSP.Address,
            // responseSP.BlockNr,
            responseSP.Signature
        );

        bytes32 resHash = getMessageHashSP(responseSP.ChannelId, responseSP.Proof, responseSP.SignedReqBody, responseSP.Address, responseSP.CurrentBlockHeight);
        emit msgHash(resHash);
        return (responseSP, resHash);
    }


    function getMessageHashSP(
        bytes32 ChannelId,
        bytes[] memory proof,
        bytes memory SignedReqBody,
        bytes memory Address,
        uint256 blockNr
    ) public pure returns (bytes32) {
        bytes memory proofBytes;
        for (uint256 i = 0; i < proof.length; i++) {
            proofBytes = abi.encodePacked(proofBytes, proof[i]);
        }

            // Step 2: Convert BlockNr to bytes
        // bytes memory blockNrBytes = abi.encodePacked(blockNr);

        return keccak256(abi.encodePacked(
            ChannelId,
            SignedReqBody,
            proofBytes
            // Address
            // blockNrBytes
        ));
    }


}