pragma solidity ^0.8.0;

contract FileUpload {
    uint256 constant CHUNK_SIZE = 1024;

    struct Chunk {
        bytes32 fileHash;
        uint index;
        bytes data;
    }

    struct FileChunked {
        bytes32 hash;
        address owner;
        uint timestamp;
        uint fileSize;
        uint chunkSize;
        uint numChunks;
    }
    struct File {
        bytes32 hash;
        address owner;
        uint timestamp;
    }

    mapping(bytes32 => File) public files;
    mapping(bytes32 => FileChunked) public filesChunked;
    mapping(address => uint) public fileCount;
    mapping(bytes32 => mapping(uint => Chunk)) public chunks;

    event ChunkUploaded(address indexed owner, bytes32 indexed hash, uint chunkIndex, uint timestamp);
    event FileUploadedToBlockchain(address indexed owner, bytes32 hash, uint timestamp);
    event FileUploaded(address indexed owner, bytes32 indexed hash, uint timestamp, uint fileSize, uint chunkSize);

    function uploadFileViaShredding(bytes memory file, uint256 chunkSize) payable public returns (bytes32) {
        bytes32 fileHash = keccak256(file);
        uint fileSize = file.length;

        // Calculate the number of chunks
        uint numChunks = (fileSize) / chunkSize;

        // Create a new file structure
        FileChunked storage newFile = filesChunked[fileHash];
        newFile.hash = fileHash;
        newFile.owner = msg.sender;
        newFile.timestamp = block.timestamp;
        newFile.fileSize = fileSize;
        newFile.chunkSize = chunkSize;
        newFile.numChunks = numChunks;

        // Save the file
        filesChunked[fileHash] = newFile;
        fileCount[msg.sender]++;

        // Emit the FileUploaded event
        emit FileUploaded(msg.sender, fileHash, block.timestamp, fileSize, chunkSize);

        // Upload the chunks
        for (uint256 i = 0; i < numChunks; i++) {
            uint offset = i * chunkSize;
            uint size = chunkSize;
            if (offset + size > fileSize) {
                size = fileSize - offset;
            }
            bytes memory chunkData = new bytes(size);
            for (uint j = 0; j < size; j++) {
                chunkData[j] = file[offset + j];
            }
            Chunk storage chunk = chunks[fileHash][i];
            chunk.fileHash = fileHash;
            chunk.index = i;
            chunk.data = chunkData;
            emit ChunkUploaded(msg.sender, fileHash, i, block.timestamp);
        }

        return fileHash;
    }

    function uploadFileSimple(bytes memory file) payable public returns (bytes32){
        // Compute the hash of the file
        bytes32 fileHash = keccak256(file);

        // Check if the file already exists
        require(files[fileHash].hash == bytes32(0), "File already exists");

        // Create a new file structure
        File memory newFile = File({
        hash : fileHash,
        owner : msg.sender,
        timestamp : block.timestamp
        });

        // Save the file
        files[fileHash] = newFile;
        fileCount[msg.sender]++;

        // Emit the FileUploaded event
        emit FileUploadedToBlockchain(msg.sender, fileHash, block.timestamp);

        return fileHash;
    }

    function checkChunkedFile(bytes memory fileHash) public view returns (bool, address, uint, uint, uint) {
        FileChunked storage file = filesChunked [keccak256(fileHash)];
        return (file.hash != bytes32(0), file.owner, file.timestamp, file.fileSize, file.chunkSize);
    }

    function checkFile(bytes32 fileHash) public view returns (bool, address, uint) {
        File storage file = files[fileHash];
        return (file.hash != bytes32(0), file.owner, file.timestamp);
    }

    function getFileCount(address user) public view returns (uint) {
        return fileCount[user];
    }

    function getHash(bytes memory fileHash) public view returns (bytes32) {
        File storage file = files[keccak256(fileHash)];
        require(file.hash != bytes32(0), "File does not exist");

        return file.hash;
    }

}
