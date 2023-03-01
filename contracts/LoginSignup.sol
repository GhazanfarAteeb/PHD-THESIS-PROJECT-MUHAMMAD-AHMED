pragma solidity ^0.8.0;

import "contracts/ECDSA.sol";
import "contracts/Strings.sol";
contract LoginSignup {
    using ECDSA for bytes32;

    struct User {
        string username;
        bytes32 hashedPassword;
        uint256 createdAt;
    }

    mapping(string => User) public users;

    function signup(string memory _username, string memory _password) public {
        require(keccak256(abi.encodePacked(users[_username].username)) == keccak256(abi.encodePacked("")), "Username already exists");
        users[_username] = User(_username, keccak256(abi.encodePacked(_password)), block.timestamp);
    }

    function login(string memory _username, string memory _password) public view returns (bool) {
        User storage user = users[_username];
        require(keccak256(abi.encodePacked(user.username)) != keccak256(abi.encodePacked("")), "Username not found");
        return user.hashedPassword == keccak256(abi.encodePacked(_password));
    }
    function getUsername(string memory _username) public view returns(string memory) {
        return users[_username].username;
    }
}