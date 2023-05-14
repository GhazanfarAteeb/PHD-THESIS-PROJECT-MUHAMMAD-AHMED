pragma solidity ^0.8.0;

import "contracts/ECDSA.sol";
import "contracts/Strings.sol";

contract LoginSignup {
    using ECDSA for bytes32;

    struct SimpleUser {
        string username;
        bytes32 hashedPassword;
        uint256 createdAt;
    }

    struct DiffieHellmanUser {
        string username;
        bytes32 hashedPassword;
        bytes32 privateKey;  // Private key for DBDH-based IBS
        uint256 createdAt;
    }

    mapping(string => SimpleUser) public simpleUsers;
    mapping(string => DiffieHellmanUser) public diffieHellmanUsers;
    mapping(address => bytes32) public privateKeys;

    function signup(string memory _username, string memory _password) public {
        require(keccak256(abi.encodePacked(simpleUsers[_username].username)) == keccak256(abi.encodePacked("")), "Username already exists");
        simpleUsers[_username] = SimpleUser(_username, keccak256(abi.encodePacked(_password)), block.timestamp);
    }

    function login(string memory _username, string memory _password) public view returns (bool) {
        SimpleUser storage user = simpleUsers[_username];
        require(keccak256(abi.encodePacked(user.username)) != keccak256(abi.encodePacked("")), "Username not found");
        return user.hashedPassword == keccak256(abi.encodePacked(_password));
    }

    function getUsername(string memory _username) public view returns (string memory) {
        return simpleUsers[_username].username;
    }

    function signupWithDBDH(string memory _username, string memory _password) public payable returns (bool) {
        require(keccak256(abi.encodePacked(diffieHellmanUsers[_username].username)) == keccak256(abi.encodePacked("")), "Username already exists");
        if (keccak256(abi.encodePacked(diffieHellmanUsers[_username].username)) == keccak256(abi.encodePacked(""))) {
            return false;
        }
        else {
            bytes32 privateKey = keccak256(abi.encodePacked(_username, _password));
            privateKeys[msg.sender] = privateKey;

            diffieHellmanUsers[_username] = DiffieHellmanUser(_username, keccak256(abi.encodePacked(_password)), privateKey, block.timestamp);
            return true;
        }
    }

    function loginWithDBDH(string memory _username, string memory _password, bytes memory _signature) public view returns (bool) {
        DiffieHellmanUser storage user = diffieHellmanUsers[_username];
        require(keccak256(abi.encodePacked(user.username)) != keccak256(abi.encodePacked("")), "Username not found");

        bytes32 messageHash = keccak256(abi.encodePacked(_username, _password));
        bytes32 signedMessageHash = messageHash.toEthSignedMessageHash();
        address signer = signedMessageHash.recover(_signature);

        // Verify the signature using the user's private key
        require(signer == address(this), "Invalid signature");
        require(privateKeys[signer] == keccak256(abi.encodePacked(_username, _password)), "Invalid private key");

        return user.hashedPassword == keccak256(abi.encodePacked(_password));
    }

}