// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "./fraud-detector/interfaces/IPayChan.sol";
import "./fraud-detector/interfaces/IDeposit.sol";
import "./fraud-detector/FraudProofTxProcessor.sol";
import "./fraud-detector/FraudProofSPProcessor.sol";
import "./fraud-detector/libs/rlp/Helper.sol";
import "./fraud-detector/libs/decode/msgDecoding.sol";
import "./fraud-detector/newHeader.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";


interface IHonkVerifier {
    function verify(
        bytes calldata _proof,
        bytes32[] calldata _publicInputs
    ) external returns (bool);
}


contract FraudProofDecoder is FraudProofTxProcessor, FraudProofSPProcessor {

    using RLPReader for bytes;
    using RLPReader for RLPReader.RLPItem;
    using FraudProofDecoderLibrary for bytes;
    using HeaderDecoder for bytes;

    IHonkVerifier public immutable zkVerifier;

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

    constructor(
        address _paychanContractAddress,
        address _depositContract,
        address _zkVerifier
    )
        FraudProofBase(_paychanContractAddress, _depositContract)
    {
        zkVerifier = IHonkVerifier(_zkVerifier);
    }

    function _decodeReqResAndChanValid(
        bytes memory res,
        bytes memory req
    ) internal returns (Context memory ctx) {
        // Step 1: Decode request
        (RequestBody memory request, bytes32 reqHash) =
            FraudProofDecoderLibrary.decodeRequest(req);
        ctx.reqHash = reqHash;

        // Step 2: Decode response
        ctx.isSP = (keccak256(abi.encodePacked(getType(res)))) != keccak256(abi.encodePacked("response"));
        if (!ctx.isSP) {
            (ResponseMsg memory response, bytes32 resHash) = FraudProofDecoderLibrary.decodeResponse(res);
            require(request.ChannelId == response.ChannelId, "Channel ID must be the same.");
            ctx.channelId     = request.ChannelId;
            ctx.signedReqBody = response.SignedReqBody;
            ctx.resSignature  = response.Signature;
            ctx.blockNr       = response.CurrentBlockHeight;
            ctx.proofKey      = response.TxIdx;
            ctx.proof         = response.Proof;
            ctx.resHash       = resHash;
        } else {
            (ResponseSPMsg memory responseSP, bytes32 resHash) = FraudProofDecoderLibrary.decodeResponseSP(res);
            require(request.ChannelId == responseSP.ChannelId, "Channel ID must be the same.");
            ctx.channelId     = request.ChannelId;
            ctx.signedReqBody = responseSP.SignedReqBody;
            ctx.resSignature  = responseSP.Signature;
            ctx.blockNr       = responseSP.CurrentBlockHeight;
            ctx.proofKey      = responseSP.Address;
            ctx.proof         = responseSP.Proof;
            ctx.resHash       = resHash;
        }
    }

    function fraudProofDetector(
        bytes memory   res,
        bytes memory   req,
        bytes memory   blockHeaderInfo,
        address        witness,

        // New for zk
        bytes calldata zkProof,
        bytes32        claimedValueHash,
        bytes32        queryKey
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
        require(responseSigner == channelInfo.recipient, "It must be a valid response from the full node.");

        // 4) Decode block header to obtain txRoot/stateRoot and recompute its headerhash
        HeaderDecoder.HeaderResults memory header = HeaderDecoder.decodeHeader(blockHeaderInfo);

        // 5) Anchor the header using blockhash(blocknr)
        bytes32 blockHash = blockhash(ctx.blockNr);
        require(blockHash == header.headerHash, "Can't trust your root values");

        // 6) Verify Merkle/MPT proof against the relevant root (tx vs state)
        // "VERIFY MERKLE PROOF"

        // _verifyZKFraudProof returns TRUE when FRAUD IS CONFIRMED.
        bytes32 trieRoot = ctx.isSP ? header.stateRoot : header.txRoot;
        bool fraudConfirmed = _verifyZKFraudProof(
            zkProof,
            trieRoot,
            claimedValueHash,
            queryKey
        );
        require(fraudConfirmed, "ZK fraud proof invalid or full node is honest.");

        // 7) Fraud -> slash FN and pay LC and witness
        slashWithAddresses(channelInfo.sender, channelInfo.recipient, witness);
    }

    function _verifyZKFraudProof(
        bytes calldata zkProof,
        bytes32        trieRoot,
        bytes32        claimedValueHash,
        bytes32        queryKey
    ) internal returns (bool) {

        // Must be exactly 96 = NUMBER_OF_PUBLIC_INPUTS(112) - PAIRING_POINTS_SIZE(16)
        // [3..95] = bytes32(0) by default
        bytes32[] memory publicInputs = new bytes32[](96);
        publicInputs[0] = trieRoot;
        publicInputs[1] = claimedValueHash;
        publicInputs[2] = queryKey;

        return zkVerifier.verify(zkProof, publicInputs);
    }

    function slashWithAddresses(
        address lc,
        address fn_,
        address witness
    ) internal {
        depositContract.slash(fn_, lc, witness);
    }

    function getType(bytes memory res) internal pure returns (string memory) {
        RLPReader.RLPItem[] memory items = res.toRlpItem().toList();
        require(items.length > 1,
            "Incorrect number of fields in RLP encoded data");
        ResponseMsg memory responseSP;
        responseSP.Type = string(items[0].toBytes());
        return responseSP.Type;
    }

    function verifyProof(
        bytes32 root,
        bytes[] memory proof,
        bytes[] memory keys
    ) public returns (bool) {
        (bool success, StorageValue[] memory values) =
            MerkleVerify.VerifyEthereumProof(root, proof, keys);
        if (success) {
            emit emitProofValues(values);
            emit LogBool(true);
            return true;
        }
        return false;
    }

    receive() external payable {}
}
