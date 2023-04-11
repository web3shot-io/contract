// SPDX-License-Identifier: MIT
pragma solidity 0.8.14;

import "Web3ShotPassport.sol";
import "Ownable.sol";

contract Web3ShotUserLevel is Ownable {
    Web3ShotPassport public WEB3_SHOT_PASSPORT;
    bytes32 public DOMAIN_SEPARATOR;
    bytes32 public TYPE_HASH;

    struct PassportLevelUpInfo {
        uint256 tokenId;
        uint256 learningPoints;
        bool connexProfile;
        uint256 connexConnections;
        uint256 level;
    }

    // modify passport level.
    mapping(address => bool) private _SIGNERS;

    mapping(address => PassportLevelUpInfo) private _PASSPORT_LEVEL_UP_INFO;

    constructor(address passportAddress) {
        WEB3_SHOT_PASSPORT = Web3ShotPassport(passportAddress);
        uint256 chainId;
        assembly {
            chainId := chainid()
        }
        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                0x8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f, // keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes("Web3ShotPassportLevel")),
                0xc89efdaa54c0f20c7adf612882df0950f5a951637e0307cdcb4c672f298b8bc6, // keccak256(bytes("1")) for versionId = 1,
                chainId,
                address(this)
            )
        );
        TYPE_HASH = keccak256("PassportLevelUp(uint256 tokenId,uint256 learningPoints,bool connexProfile,uint256 connexConnections)");
    }

    function setPassportLevelByUser(
        uint256 tokenId,
        uint256 learningPoints,
        bool connexProfile,
        uint256 connexConnections,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        address owner = WEB3_SHOT_PASSPORT.ownerOf(tokenId);
        require(owner == msg.sender, "caller is not token owner");
        // check previous status
        PassportLevelUpInfo memory info = _PASSPORT_LEVEL_UP_INFO[owner];
        require(info.learningPoints <= learningPoints, "learningPoints is less than prev");
        if (info.connexProfile) {
            require(connexProfile, "invalid connexProfile: false");
        }
        require(info.connexConnections <= connexConnections, "connexConnections is less than prev");

        // check signature
        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                DOMAIN_SEPARATOR,
                keccak256(abi.encode(TYPE_HASH, tokenId, learningPoints, connexProfile, connexConnections))
            )
        );
        require(_SIGNERS[ecrecover(digest, v, r, s)], "invalid signature");

        // check level up, 10 learningPoints to 1 level
        learningPoints = learningPoints / 10;
        uint256 level = 1 + learningPoints + connexConnections;
        if (connexProfile) {
            level += 10;
        }
        require(info.level < level, "level is less than or equal to prev");

        _PASSPORT_LEVEL_UP_INFO[owner] = PassportLevelUpInfo(tokenId, learningPoints * 10, connexProfile, connexConnections, level);
        WEB3_SHOT_PASSPORT.setPassportLevel(tokenId, uint32(level));
    }

    /**
     * @dev Add a new signer.
     */
    function addSigner(address signer) external onlyOwner {
        require(!_SIGNERS[signer], "signer already added");
        _SIGNERS[signer] = true;
    }

    /**
     * @dev Remove a old signer.
     */
    function removeSigner(address signer) external onlyOwner {
        require(_SIGNERS[signer], "signer does not exist");
        delete _SIGNERS[signer];
    }

    function isSigner(address signer) external view returns (bool) {
        return _SIGNERS[signer];
    }

    /**
     * @dev Update passport contract address.
     */
    function updatePassportAddress(address passportAddress) external onlyOwner {
        WEB3_SHOT_PASSPORT = Web3ShotPassport(passportAddress);
    }

    function getLevelUpInfo(address user) external view returns (PassportLevelUpInfo memory) {
        return _PASSPORT_LEVEL_UP_INFO[user];
    }
}
