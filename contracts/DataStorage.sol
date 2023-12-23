// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract DataStorage {
    // Define a mapping to store dynamic arrays of bytes data
    mapping(address => bytes[]) public byteDataArray;

    // Mapping to store the index of each stored bytes data
    mapping(address => mapping(bytes => uint256)) public dataIndex;
    // Event to log data storage
    event DataStored(address indexed user, bytes data, uint256 index);

    // Function to store bytes data
    function storeBytes(bytes memory _data) public payable {
        // Store data for the sender
        byteDataArray[msg.sender].push(_data);
        uint256 index = byteDataArray[msg.sender].length - 1;

        // Store the index of the data
        dataIndex[msg.sender][_data] = index;

        // Emit an event to log the data storage
        emit DataStored(msg.sender, _data, index);
    }

    // Function to retrieve specific element from the stored bytes array and its index
    function getBytes(bytes memory _data) public view returns (bytes memory) {
        for (uint256 i = 0; i < byteDataArray[msg.sender].length; i++) {
            if (keccak256(byteDataArray[msg.sender][i]) == keccak256(_data)) {
                // Return the first matching data found
                return byteDataArray[msg.sender][i];
            }
        }
        revert("Data not found");
    }
}
