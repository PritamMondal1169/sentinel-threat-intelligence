// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Stores only hash commitments of SENTINEL reports. Proves integrity and ordering, not the truth of a threat claim.
contract ReportRegistry {
    struct Commitment {
        bytes32 contentHash;
        bytes32 prevHash;
        uint32 version;
        uint8 category;
        address submitter;
        uint64 timestamp;
    }

    mapping(bytes32 => Commitment[]) private history;

    event ReportCommitted(bytes32 indexed reportId, uint32 version, bytes32 contentHash, address submitter);

    function commit(bytes32 reportId, bytes32 contentHash, uint8 category) external returns (uint32 version) {
        Commitment[] storage h = history[reportId];
        if (h.length > 0) require(h[h.length - 1].submitter == msg.sender, "not owner");
        bytes32 prev = h.length == 0 ? bytes32(0) : h[h.length - 1].contentHash;
        version = uint32(h.length + 1);
        h.push(Commitment(contentHash, prev, version, category, msg.sender, uint64(block.timestamp)));
        emit ReportCommitted(reportId, version, contentHash, msg.sender);
    }

    function latest(bytes32 reportId) external view returns (Commitment memory) {
        Commitment[] storage h = history[reportId];
        require(h.length > 0, "unknown report");
        return h[h.length - 1];
    }

    function getVersion(bytes32 reportId, uint32 version) external view returns (Commitment memory) {
        Commitment[] storage h = history[reportId];
        require(version >= 1 && version <= h.length, "bad version");
        return h[version - 1];
    }

    function versionCount(bytes32 reportId) external view returns (uint256) {
        return history[reportId].length;
    }
}
