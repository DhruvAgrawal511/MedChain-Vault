// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract BlockVault {
    using ECDSA for bytes32;

    struct FileRecord {
        address uploader;
        bytes signature;
        string ipfsCID;
        uint256 timestamp;
    }

    mapping(bytes32 => FileRecord) private files;

    event FileUploaded(
        bytes32 indexed fileHash,
        address indexed uploader,
        string ipfsCID,
        bytes signature,
        uint256 timestamp
    );
    event Debug(string msg, bytes32 hash, address who);

    function uploadFile(
        bytes32 fileHash,
        string calldata ipfsCID,
        bytes calldata signature
    ) external {
        emit Debug("Before require", fileHash, msg.sender);
        require(files[fileHash].uploader == address(0), "File already uploaded");

        files[fileHash] = FileRecord({
            uploader: msg.sender,
            signature: signature,
            ipfsCID: ipfsCID,
            timestamp: block.timestamp
        });

        emit FileUploaded(fileHash, msg.sender, ipfsCID, signature, block.timestamp);
    }


    /**
     * @dev Fetch file record details by hash.
     * @param fileHash The keccak256 hash of the file.
     */
    function getFileRecord(bytes32 fileHash)
        external
        view
        returns (
            address uploader,
            string memory ipfsCID,
            bytes memory signature,
            uint256 timestamp
        )
    {
        FileRecord storage rec = files[fileHash];
        return (rec.uploader, rec.ipfsCID, rec.signature, rec.timestamp);
    }

    /**
     * @dev Verify a file hash was signed by the uploader.
     * @param fileHash The keccak256 hash of the file content.
     * @param signature The digital signature.
     * @param expectedSigner The uploader's wallet address.
     */
    function verifySignature(
        bytes32 fileHash,
        bytes memory signature,
        address expectedSigner
    ) public pure returns (bool) {
        // Manually compute the Ethereum Signed Message Hash
        // This is equivalent to what toEthSignedMessageHash does for a bytes32 hash
        bytes32 ethSignedHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", fileHash));

        // Then, recover the signer from the ethSignedHash and the signature
        return ethSignedHash.recover(signature) == expectedSigner;
    }
}