// SPDX-License-Identifier: MIT

/*  TODO
    CURRENT:    ship proof (array of trie nodes) on-chain and the EVM verifies it
    GOAL:       ship a fixed size ZK proof that attests the trie proof was checked correclty:
        1) Off chain witness node generates proof: given header roots, response proof nodes + key, the trie verification fails
        2) On-chain verifier checks ZK proof and slashes
*/

/*
Max's comments:

LC needs the following to generate a VALID fraud proof:
    - LC MUST VERIFY that request hash matches the expected one (Verify Request Hash)
    - LC MUST VERIFY that the response contains a valid signature from FN (Verify Response Hash)
    - LC MUST VERIFY that the channelID of the response matches the request (Verify Response Signature)
    
LC generates a fraud proof when (FRAUD):
    - The payment amount in the response doesn't match the cumulative amount signed by LC in request (Payment Amount Check)
    - Block height of response > block height indicated in the request by the block hash (Timestamp Check)
    - Response MUST contain a Merkle proof proving data is part of tree specified by the request type, either transaction trie or state trie "isSP"
        at the current block height in the response (VERIFY MERKLE PROOF)

=> FRAUD DETECTED -> LC calls fraudProofDetector(response, request, blockheader, witness) on line 111-...

*/
pragma solidity ^0.8.17;

import "./fraud-detector/interfaces/IPayChan.sol";
import "./fraud-detector/interfaces/IDeposit.sol";
import "./fraud-detector/FraudProofTxProcessor.sol";
import "./fraud-detector/FraudProofSPProcessor.sol";

import "./fraud-detector/libs/rlp/Helper.sol";  // Assuming you have added an RLP decoding library

import "./fraud-detector/libs/decode/msgDecoding.sol";

import "./fraud-detector/newHeader.sol";

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

// "Payment Amount Check" happens in XProcessor
contract FraudProofDecoder is FraudProofTxProcessor, FraudProofSPProcessor {

    using RLPReader for bytes;
    using RLPReader for RLPReader.RLPItem;

    using FraudProofDecoderLibrary for bytes;
    using HeaderDecoder for bytes;


    struct Context {
        bytes signedReqBody;
        bytes resSignature;
        uint256 blockNr;
        bytes32 reqHash;
        bytes32 resHash;
        bool isSP;
        bytes32 channelId;
        bytes proofKey;
        bytes[] proof;
    }

    constructor(address _paychanContractAddress, address _depositContract)
        FraudProofBase(_paychanContractAddress, _depositContract)
    {}
    // address constant public fullNode = 0xC8A7ae3f6Ae079c20BA19164089143F48F7B965f;
    // address constant public lightClient = 0xD25a31702b7b86B2e953Baf9ff88Ef716A5306Cc;


    /*

    Max's comments: 

    As seen in "libs/decode/msgDecoding.sol" (REQUEST line 102-133, RESPONSE line 12-76):
    THE REQUEST:    ChannelId (uint32), Amount (uint), LocalBlockHash (bytes), ReqBytes (bytes) 
    THE RESPONSE:   ChannelId (bytes32), Amount (uint), SignedReqBody (bytes)(sig on req hqsh), CurrentBlockHeight (uint), ReturnValue (bytes), 
                        Proof (array), TxIdx (uint32)(key), Signature (bytes)(Fn sig), TxRootHash (bytes)

    "RESPONSESP" (isSP):     ChannelId (bytes32), Amount (uint), ReqBodyHash (bytes), SignedReqBody (bytes), CurrentBlockHeight (uint),
                                ReturnValue (bytes), Proof (array), Address (bytes)(key), Signature (bytes), TxRootHash (bytes)
        => similar but uses Address(key) and inteded for state proof (isSP)

    */

    function _decodeReqResAndChanValid (
        bytes memory res,
        bytes memory req
    ) internal returns (Context memory ctx) {
        // Step 1: Decode Request
        (RequestBody memory request, bytes32 reqHash) = FraudProofDecoderLibrary.decodeRequest(req);
        ctx.reqHash = reqHash;

        // Step 2: Decode Response
        // TODO replace responseMsg proof [][]byte + TxIdx []byte WITH ZKproof []byte of fixed size
        ctx.isSP = (keccak256(abi.encodePacked(getType(res)))) != keccak256(abi.encodePacked("response"));
        if (!ctx.isSP) {
            (ResponseMsg memory response, bytes32 resHash) = FraudProofDecoderLibrary.decodeResponse(res);
            require(request.ChannelId == response.ChannelId, "Channel ID must be the same.");
            ctx.channelId = request.ChannelId;
            ctx.signedReqBody = response.SignedReqBody;
            ctx.resSignature = response.Signature;
            ctx.blockNr = response.CurrentBlockHeight;
            ctx.proofKey = response.TxIdx;
            ctx.proof = response.Proof;
            ctx.resHash = resHash;
        } else {
            (ResponseSPMsg memory responseSP, bytes32 resHash) = FraudProofDecoderLibrary.decodeResponseSP(res);
            require(request.ChannelId == responseSP.ChannelId, "Channel ID must be the same.");
            ctx.channelId = request.ChannelId;
            ctx.signedReqBody = responseSP.SignedReqBody;
            ctx.resSignature = responseSP.Signature;
            ctx.blockNr = responseSP.CurrentBlockHeight;
            ctx.proofKey = responseSP.Address;
            ctx.proof = responseSP.Proof;
            ctx.resHash = resHash;
        }
    }

    /*
    Max's comments:
    
    fraudProofDetector(response, request, blockheader, witness):
        1) Decode request and response (=RLP blobs), see "_decodeReqResAndChanValid" above 
        2) Get channel participants from the on-chain paychannel (Who is LC/FN)
        3) Link them via hashes and signatures (client signed request hash, full node signed response hash)
        4) Decode block header to obtain txRoot/stateRoot and recompute its headerhash
        5) Anchor the header using blockhash(blocknr)
        6) Verify Merkle/MPT proof against the relevant root (tx vs state)
        7) Failure -> slash FN and pay LC and witness

    */

    function fraudProofDetector(
        bytes memory res,               // RLP encoded PARP response 
        bytes memory req,               // RLP encoded PARP request
        bytes memory blockHeaderInfo,   // RLP encoded ETH block header (height)
        address witness
        ) public {        
        
        // 1) Decode request and response
        // "Verify Response Signature"
        Context memory ctx = _decodeReqResAndChanValid(res, req);

        // 2) Get channel participants from the on-chain paychannel (Who is LC/FN)
        ChannelInfo memory channelInfo;
        (channelInfo.sender, channelInfo.recipient, channelInfo.status, ) = paychanContract.paychanSelectedArguments(ctx.channelId);
        require(channelInfo.status != 0, "The channel must not be closed.");

        // 3) Link them via hashes and signatures (client signed request hash, full node signed response hash)
        // signedreqBody is the signqture over reqHash (LC) -> "Verify Request Hash"
        // resSignedBody is the signature over resHash (FN) -> "Verify Response Hash"
        address requestSigner = ECDSA.recover(ctx.reqHash, ctx.signedReqBody);
        require(requestSigner == channelInfo.sender, "It must be a valid request from the light client.");

        address responseSigner = ECDSA.recover(ctx.resHash, ctx.resSignature);
        require(responseSigner == channelInfo.recipient, "It must be a vaid response from the full node.");


        // 4) Decode block header to obtain txRoot/stateRoot and recompute its headerhash
        HeaderDecoder.HeaderResults memory header = HeaderDecoder.decodeHeader(blockHeaderInfo);

        // 5) Anchor the header using blockhash(blocknr)
        bytes32 blockHash = blockhash(ctx.blockNr);
        require(blockHash == header.headerHash, "Cant trust your root values");
        
        // 6) Verify Merkle/MPT proof against the relevant root (tx vs state)
        // "VERIFY MERKLE PROOF"
        // TODO Replace with verify NOIR proof
        bool proofStatus;
        proofStatus = verifyFraudDetection(ctx.isSP, header, ctx.proofKey, ctx.proof);
        // If proofStatus is true, it means the merkle proof is not a fraud
        require(proofStatus == false, "Fraud proof is valid. Full node is honest.");

        // 7) Failure -> slash FN and pay LC and witness
        slashWithAddresses(channelInfo.sender, channelInfo.recipient, witness);
    }
    
    function verifyFraudDetection(
        bool isSP,
        HeaderDecoder.HeaderResults memory header, 
        bytes memory proofKey,
        bytes[] memory proof
    ) internal returns (bool) {
        bool proofStatus;
        bytes[] memory key = new bytes[](1);

        key[0] = proofKey;
        if (!isSP) {
            proofStatus = FraudProofHelper.verifyProof(header.txRoot, proof, key);
        } else {
            proofStatus = FraudProofHelper.verifyProof(header.stateRoot, proof, key);
        }
        emit LogBool(proofStatus);
        return proofStatus;
    }

    function slashWithAddresses(address lc, address fn, address witness) internal {
        depositContract.slash(fn, lc, witness);
    }

    function getType(bytes memory res) internal pure returns (string memory) {
        RLPReader.RLPItem[] memory items = res.toRlpItem().toList();

        // Ensure the correct number of fields
        require(items.length > 1, "Incorrect number of fields in RLP encoded data");

        ResponseMsg memory responseSP;

        // Decode fields
        responseSP.Type = string(items[0].toBytes());
        
        return responseSP.Type;
    }


    receive() external payable {}

    function verifyProof(
        bytes32 root,
        bytes[] memory proof,
        bytes[] memory keys
    ) public returns (bool) {
        // verifies ethereum specific merkle patricia proofs as described by EIP-1188.
        // can be used to verify the receipt trie, transaction trie and state trie
        // contributed by @ripa1995
        (bool success, StorageValue[] memory values) = MerkleVerify.VerifyEthereumProof(root, proof, keys);
        // do something with the verified values.
        // Emit the event to log the values
        if (success) {
            emit emitProofValues(values);
            emit LogBool(true);
            return true;
        } else {
            return false;
        }
    }

}

