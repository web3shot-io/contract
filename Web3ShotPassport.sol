// SPDX-License-Identifier: MIT
pragma solidity 0.8.14;

import {IERC20, SafeERC20} from "SafeERC20.sol";
import "IERC721.sol";
import "IERC721Receiver.sol";
import "IERC721Metadata.sol";
import "Address.sol";
import "Context.sol";
import "Strings.sol";
import "ERC165.sol";
import "Ownable.sol";

contract Web3ShotPassport is Ownable, ERC165, IERC721, IERC721Metadata {
    using SafeERC20 for IERC20;
    using Address for address;
    using Strings for uint256;

    /* ============ State Variables ============ */

    struct Passport {
        uint160 owner; // address is 20 bytes long
        uint32 status;
        uint32 level; // passport level
    }

    struct PassportUpdated {
        address signer;
        uint256 tokenId;
        uint32 level;
        uint8 v; // v: parameter (27 or 28)
        bytes32 r; // r: parameter
        bytes32 s; // s: parameter
    }

    bytes32 public constant PASSPORT_HASH = keccak256("PassportUpdated(address signer,uint256 tokenId,uint32 level)");

    // Token name
    string private _name;

    // Token symbol
    string private _symbol;

    // Total number of tokens burned
    uint256 private _burnCount;

    // Array of all tokens storing the owner's address and the campaign id
    Passport[] private _tokens;

    // Mapping owner address to token count
    mapping(address => uint256) private _balances;

    // Mapping owner address to passport token id
    mapping(address => uint256) private _passports;

    // modify passport level.
    mapping(address => bool) private _signers;
    // mapping(address => mapping(uint256 => bool)) private _isUserOrderNonceExecuted;

    // Base token URI
    string private _baseURI;

    /* ============ Events ============ */
    // Add new signer
    event EventSignerAdded(address indexed newSigner);

    // Remove old signer
    event EventSignerRemoved(address indexed oldSigner);

    // Passport level updated
    event EventPassportLevelUpdated(uint256 tokenId, uint32 level);

    // Passport created
    event Mint(address indexed owner, uint256 tokenId, uint32 status, uint32 level);

    // Passport burned
    event Burn(address indexed owner, uint256 tokenId);

    // Passport revoked
    event Revoke(address indexed owner, uint256 tokenId);

    uint256 public immutable maxMintAmount = 10**5;
    uint256 public immutable freeMintAmount = 10**4;
    uint256 public mintPrice;
    uint256 public mintTime;
    address public mintToken;
    bytes32 public DOMAIN_SEPARATOR;

    /**
     * @dev Initializes the contract
     */
    constructor(
        string memory n,
        string memory s,
        uint256 _mintPrice,
        address _mintToken,
        uint256 _mintTime
    ) {
        // Initialize zero index value
        Passport memory _passport = Passport(0, 0, 0);
        _tokens.push(_passport);
        mintPrice = _mintPrice;
        mintToken = _mintToken;
        _name = n;
        _symbol = s;
        mintTime = _mintTime;
        // Calculate the domain separator
        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                0x8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f, // keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")
                keccak256("Web3ShotPassport"),
                0xc89efdaa54c0f20c7adf612882df0950f5a951637e0307cdcb4c672f298b8bc6, // keccak256(bytes("1")) for versionId = 1
                block.chainid,
                address(this)
            )
        );
    }

    /**
     * @dev See {IERC165-supportsInterface}.
     */
    function supportsInterface(bytes4 interfaceId) public view override(ERC165, IERC165) returns (bool) {
        return
            interfaceId == type(IERC721).interfaceId || interfaceId == type(IERC721Metadata).interfaceId || super.supportsInterface(interfaceId);
    }

    /**
     * @dev Is this contract allow nft transfer.
     */
    function transferable() public view returns (bool) {
        return false;
    }

    /**
     * @dev Returns the base URI for nft.
     */
    function baseURI() public view returns (string memory) {
        return _baseURI;
    }

    /**
     * @dev Get Passport status.
     */
    function passportStatus(uint256 tokenId) public view returns (uint32) {
        require(_exists(tokenId), "Web3ShotPassport: passport does not exist");
        return _tokens[tokenId].status;
    }

    /**
     * @dev Get Passport status.
     */
    function passportLevel(uint256 tokenId) public view returns (uint32) {
        require(_exists(tokenId), "Web3ShotPassport: passport does not exist");
        return _tokens[tokenId].level;
    }

    /**
     * @dev Get Passport minted count.
     */
    function getNumMinted() public view returns (uint256) {
        return _tokens.length - 1;
    }

    /**
     * @dev See {IERC721Enumerable-totalSupply}.
     */
    function totalSupply() public view returns (uint256) {
        return getNumMinted() - _burnCount;
    }

    /**
     * @dev See {IERC721Enumerable-tokenOfOwnerByIndex}.
     * This is implementation is O(n) and should not be
     * called by other contracts.
     */
    function tokenOfOwnerByIndex(address owner, uint256 index) public view returns (uint256) {
        uint256 currentIndex = 0;
        for (uint256 i = 1; i < _tokens.length; i++) {
            if (isOwnerOf(owner, i)) {
                if (currentIndex == index) {
                    return i;
                }
                currentIndex += 1;
            }
        }
        revert("ERC721Enumerable: owner index out of bounds");
    }

    /**
     * @dev See {IERC721-balanceOf}.
     */
    function balanceOf(address owner) public view override returns (uint256) {
        require(owner != address(0), "ERC721: balance query for the zero address");
        return _balances[owner];
    }

    /**
     * @dev See {IERC721-ownerOf}.
     */
    function ownerOf(uint256 tokenId) public view override returns (address) {
        require(_exists(tokenId), "ERC721: owner query for nonexistent token");
        return address(_tokens[tokenId].owner);
    }

    /**
     * @dev See {IGalxePassport-isOwnerOf}.
     */
    function isOwnerOf(address account, uint256 id) public view returns (bool) {
        address owner = ownerOf(id);
        return owner == account;
    }

    /**
     * @dev See {IERC721Metadata-name}.
     */
    function name() public view virtual override returns (string memory) {
        return _name;
    }

    /**
     * @dev See {IERC721Metadata-symbol}.
     */
    function symbol() public view virtual override returns (string memory) {
        return _symbol;
    }

    /**
     * @dev See {IERC721Metadata-tokenURI}.
     */
    function tokenURI(uint256 tokenId) public view override returns (string memory) {
        require(_exists(tokenId), "ERC721Metadata: URI query for nonexistent token");

        return bytes(_baseURI).length > 0 ? string(abi.encodePacked(_baseURI, tokenId.toString(), ".json")) : "";
    }

    /**
     * @dev See {IERC721-approve}.
     */
    function approve(address to, uint256 tokenId) public override {
        require(false, "Web3ShotPassport: approve is not allowed");
    }

    /**
     * @dev See {IERC721-getApproved}.
     */
    function getApproved(uint256 tokenId) public view override returns (address) {
        require(false, "Web3ShotPassport: getApproved is not allowed");
    }

    /**
     * @dev See {IERC721-setApprovalForAll}.
     */
    function setApprovalForAll(address operator, bool approved) public override {
        require(false, "Web3ShotPassport: setApprovalForAll is not allowed");
    }

    /**
     * @dev See {IERC721-isApprovedForAll}.
     */
    function isApprovedForAll(address owner, address operator) public view override returns (bool) {
        return false;
    }

    /**
     * @dev See {IERC721-transferFrom}.
     */
    function transferFrom(
        address from,
        address to,
        uint256 tokenId
    ) public override {
        require(false, "Web3ShotPassport: passport is not transferrable");
    }

    /**
     * @dev See {IERC721-safeTransferFrom}.
     */
    function safeTransferFrom(
        address from,
        address to,
        uint256 tokenId
    ) public override {
        require(false, "Web3ShotPassport: passport is not transferrable");
    }

    /**
     * @dev See {IERC721-safeTransferFrom}.
     */
    function safeTransferFrom(
        address from,
        address to,
        uint256 tokenId,
        bytes memory _data
    ) public override {
        require(false, "Web3ShotPassport: passport is not transferrable");
    }

    /**
     * @dev Returns whether `tokenId` exists.
     *
     * Tokens start existing when they are minted (`_mint`),
     * and stop existing when they are burned (`_burn`).
     */
    function _exists(uint256 tokenId) internal view returns (bool) {
        return tokenId > 0 && tokenId <= getNumMinted() && _tokens[tokenId].owner != 0x0;
    }

    /**
     * @dev Returns whether `spender` owns `tokenId`.
     *
     * Requirements:
     *
     * - `tokenId` must exist.
     */
    function _isOwner(address spender, uint256 tokenId) internal view returns (bool) {
        address owner = ownerOf(tokenId);
        return spender == owner;
    }

    /* ============ External Functions ============ */

    /**
     * @dev Mints passport to `account`.
     *
     * Emits a {Mint} and a {Transfer} event.
     */
    function freeMint() external returns (uint256) {
        require(block.timestamp >= mintTime, "Web3ShotPassport: not open");
        require(getNumMinted() < freeMintAmount, "Web3ShotPassport: exceed free mint amount");
        require(balanceOf(msg.sender) == 0, "Web3ShotPassport: max mint per wallet reached");

        uint256 tokenId = _tokens.length;
        uint32 status = 1;
        uint32 level = 1;
        Passport memory passport = Passport(uint160(msg.sender), status, level);

        _balances[msg.sender] += 1;
        _passports[msg.sender] = tokenId;
        _tokens.push(passport);

        emit Mint(msg.sender, tokenId, status, level);
        emit Transfer(address(0), msg.sender, tokenId);
        return tokenId;
    }

    /**
     * @dev Mints passport to `account`.
     *
     * Emits a {Mint} and a {Transfer} event.
     */
    function mint() external returns (uint256) {
        require(block.timestamp >= mintTime, "Web3ShotPassport: not open");
        require(getNumMinted() < maxMintAmount, "Web3ShotPassport: exceed max mint amount");
        require(balanceOf(msg.sender) == 0, "Web3ShotPassport: max mint per wallet reached");
        IERC20(mintToken).safeTransferFrom(msg.sender, address(this), mintPrice);

        uint256 tokenId = _tokens.length;
        uint32 status = 1;
        uint32 level = 1;
        Passport memory passport = Passport(uint160(msg.sender), status, level);

        _balances[msg.sender] += 1;
        _passports[msg.sender] = tokenId;
        _tokens.push(passport);

        emit Mint(msg.sender, tokenId, status, level);
        emit Transfer(address(0), msg.sender, tokenId);
        return tokenId;
    }

    /**
     * @dev Burns passport with tokenId.
     *
     * Requirements:
     *
     * - msg sender must be token owner.
     * - `tokenId` token must exist.
     *
     *
     * Emits a {Burn} and a {Transfer} event.
     */
    function burn(uint256 tokenId) external {
        require(isOwnerOf(_msgSender(), tokenId), "Web3ShotPassport: caller is not token owner");

        _burnCount++;
        _balances[_msgSender()] -= 1;
        delete _passports[_msgSender()];
        _tokens[tokenId].owner = 0;
        _tokens[tokenId].status = 0;
        _tokens[tokenId].level = 0;

        emit Burn(_msgSender(), tokenId);
        emit Transfer(_msgSender(), address(0), tokenId);
    }

    function getAddressPassport(address owner) public view returns (Passport memory) {
        require(balanceOf(owner) != 0, "Web3ShotPassport: address does not have passport");
        uint256 tokenId = _passports[owner];
        return _tokens[tokenId];
    }

    /**
     * @dev Transfers `tokenId` from `from` to `to`.
     *  As opposed to {transferFrom}, this imposes no restrictions on msg.sender.
     *
     * Requirements:
     *
     * - `to` cannot be the zero address.
     * - `tokenId` token must be owned by `from`.
     *
     * Emits a {Transfer} event.
     */
    function _transfer(
        address from,
        address to,
        uint256 tokenId
    ) internal virtual {
        require(false, "Web3ShotPassport: passport is not transferrable");
    }

    /* ============ Util Functions ============ */
    /**
     * @dev Sets a new baseURI for all token types.
     */
    function setURI(string calldata newURI) external onlyOwner {
        _baseURI = newURI;
    }

    /**
     * @dev Sets a new name for all token types.
     */
    function setName(string calldata newName) external onlyOwner {
        _name = newName;
    }

    /**
     * @dev Sets a new symbol for all token types.
     */
    function setSymbol(string calldata newSymbol) external onlyOwner {
        _symbol = newSymbol;
    }

    /**
     * @dev Sets level of passport with `tokenId` to `level`.
     *
     * Requirements:
     *
     * - msg sender must be signer.
     * - `tokenId` token must exist.
     *
     *
     * Emits a {EventPassportLevelUpdated} event.
     */
    function setPassportLevel(uint256 tokenId, uint32 level) external {
        require(_exists(tokenId), "Web3ShotPassport: passport does not exist");
        require(_signers[msg.sender], "Web3ShotPassport: must be signer");
        _tokens[tokenId].level = level;
        emit EventPassportLevelUpdated(tokenId, level);
    }

    /**
     * @dev Sets level of passport with `tokenId` to `level`.
     *
     * Requirements:
     *
     * - msg sender must be owner.
     * - `tokenId` token must exist.
     *
     *
     * Emits a {EventPassportLevelUpdated} event.
     */
    function setPassportLevelByUser(PassportUpdated calldata passportUpdated, bytes32 dataHash) external {
        require(_exists(passportUpdated.tokenId), "Web3ShotPassport: passport does not exist");
        require(isOwnerOf(_msgSender(), passportUpdated.tokenId), "Web3ShotPassport: caller is not token owner");
        require(_signers[passportUpdated.signer], "Web3ShotPassport: must be signer");
        // require(!_isUserOrderNonceExecuted[passportUpdated.signer][passportUpdated.nonce], "Web3ShotPassport: nonce used");

        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, dataHash));
        require(recover(digest, passportUpdated.v, passportUpdated.r, passportUpdated.s) == passportUpdated.signer, "Signature: Invalid");

        // _isUserOrderNonceExecuted[passportUpdated.signer][passportUpdated.nonce] = true;
        _tokens[passportUpdated.tokenId].level = passportUpdated.level;
        emit EventPassportLevelUpdated(passportUpdated.tokenId, passportUpdated.level);
    }

    /**
     * @dev Add a new signer.
     */
    function addSigner(address signer) external onlyOwner {
        require(signer != address(0), "signer must not be null address");
        require(!_signers[signer], "signer already added");
        _signers[signer] = true;
        emit EventSignerAdded(signer);
    }

    /**
     * @dev Remove a old signer.
     */
    function removeSigner(address signer) external onlyOwner {
        require(_signers[signer], "signer does not exist");
        delete _signers[signer];
        emit EventSignerRemoved(signer);
    }

    // function isUserOrderNonceExecuted(address signer, uint256 nonce) external view returns (bool) {
    //     return _isUserOrderNonceExecuted[signer][nonce];
    // }

    /**
     * @dev Withdraw fee token.
     */
    function withdraw(uint256 amount) external onlyOwner {
        IERC20(mintToken).safeTransferFrom(address(this), msg.sender, amount);
    }

    function getChainId() external view returns (uint256) {
        return block.chainid;
    }

    function getHash(
        address signer,
        uint256 tokenId,
        uint32 level
    ) public view returns (bytes32) {
        return keccak256(abi.encode(PASSPORT_HASH, signer, tokenId, level));
    }

    /**
     * @notice Recovers the signer of a signature (for EOA)
     * @param hash the hash containing the signed mesage
     * @param v parameter (27 or 28). This prevents maleability since the public key recovery equation has two possible solutions.
     * @param r parameter
     * @param s parameter
     */
    function recover(
        bytes32 hash,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) internal pure returns (address) {
        // https://ethereum.stackexchange.com/questions/83174/is-it-best-practice-to-check-signature-malleability-in-ecrecover
        // https://crypto.iacr.org/2019/affevents/wac/medias/Heninger-BiasedNonceSense.pdf
        require(uint256(s) <= 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0, "Signature: Invalid s parameter");

        require(v == 27 || v == 28, "Signature: Invalid v parameter");

        // If the signature is valid (and not malleable), return the signer address
        address signer = ecrecover(hash, v, r, s);
        require(signer != address(0), "Signature: Invalid signer");

        return signer;
    }
}
