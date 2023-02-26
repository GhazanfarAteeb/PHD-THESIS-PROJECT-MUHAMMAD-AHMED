pragma solidity ^0.8.0;

contract FileUpload {
    struct File {
        bytes32 hash;
        address owner;
        uint timestamp;
    }

    mapping(bytes32 => File) public files;
    mapping(address => uint) public fileCount;
    event FileUploaded(address indexed owner, bytes32 indexed hash, uint timestamp);

    constructor() payable {}

    function uploadFile(bytes memory file) public {
        // Compute the hash of the file
        bytes32 fileHash = keccak256(file);

        // Check if the file already exists
        require(files[fileHash].hash == 0);

        // Create a new file structure
        File memory newFile = File({
            hash: fileHash,
            owner: msg.sender,
            timestamp: block.timestamp
        });

        // Save the file
        files[fileHash] = newFile;
        fileCount[msg.sender]++;

        // Emit the FileUploaded event
        emit FileUploaded(msg.sender, fileHash, block.timestamp);
    }

    function checkFile(bytes32 fileHash) public view returns (bool, address, uint) {
        File storage file = files[fileHash];
        return (file.hash != 0, file.owner, file.timestamp);
    }

    function getFileCount(address user) public view returns (uint) {
        return fileCount[user];
    }
}