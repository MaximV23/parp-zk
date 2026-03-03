// SPDX-License-Identifier: MIT

pragma solidity ^0.8.17;

// Barretenberg verifier interface
interface INoirVerifier{
    function verify(bytes calldata _proof, bytes32[] calldata _publicInputs) external view returns (bool);
}