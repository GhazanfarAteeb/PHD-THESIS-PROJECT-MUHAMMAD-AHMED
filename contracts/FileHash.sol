pragma solidity ^0.8.0;

contract FileHash {
    bytes32 private fileHash;

    function setHash(bytes32 hash) public {
        fileHash = hash;
    }

    function getHash() public view returns (bytes32) {
        return fileHash;
    }
}