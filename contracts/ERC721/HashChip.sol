// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/token/ERC721/extensions/ERC721Enumerable.sol";
import "@openzeppelin/contracts/security/Pausable.sol";
import "@openzeppelin/contracts/utils/Counters.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

contract HashChipNFT is
    Ownable,
    ERC721Enumerable,
    AccessControl,
    Pausable
{
    using Counters for Counters.Counter;
    using EnumerableSet for EnumerableSet.UintSet;

    // Count token id
    Counters.Counter private _tokenIds;
    bytes32 public constant MANAGERMENT_ROLE = keccak256("MANAGERMENT_ROLE");

    constructor(string memory name, string memory symbol) ERC721(name, symbol) {
        _setRoleAdmin(MANAGERMENT_ROLE, MANAGERMENT_ROLE);
        _setupRole(MANAGERMENT_ROLE, _msgSender());
    }

    // Mapping list token of address
    mapping(address => EnumerableSet.UintSet) private _listTokensOfAddress;

    // Event create General Hash
    event createGeneralHash(address _address, uint256 _tokenId, uint256 _type);

    // Get list Tokens of address
    function getListTokensOfAddress(
        address _address
    ) public view returns (uint256[] memory) {
        return _listTokensOfAddress[_address].values();
    }

    /**
     *@dev See {ERC721-_beforeTokenTransfer}.
     */
    function _beforeTokenTransfer(
        address from,
        address to,
        uint256 firstTokenId,
        uint256 batchSize
    ) internal virtual override {
        super._beforeTokenTransfer(from, to, firstTokenId, batchSize);
        _listTokensOfAddress[to].add(firstTokenId);
        _listTokensOfAddress[from].remove(firstTokenId);
    }

    // Base URI
    string private _baseURIextended;

    function setBaseURI(string memory baseURI_) external onlyOwner {
        _baseURIextended = baseURI_;
    }

    function _baseURI() internal view virtual override returns (string memory) {
        return _baseURIextended;
    }

    function supportsInterface(
        bytes4 interfaceId
    ) public view override(AccessControl, ERC721Enumerable) returns (bool) {
        return super.supportsInterface(interfaceId);
    }

    function pause() public onlyRole(MANAGERMENT_ROLE) {
        _pause();
    }

    function unpause() public onlyRole(MANAGERMENT_ROLE) {
        _unpause();
    }

    /*
     * base mint a General hash
     * @param _address: owner of NFT
     */

    function _createNFT(address _address) private returns (uint256) {
        uint256 tokenId = _tokenIds.current();
        _mint(_address, tokenId);
        _tokenIds.increment();
        _listTokensOfAddress[_address].add(tokenId);
        return tokenId;
    }

    /*
     * mint a General hash
     * @param _address: owner of NFT
     */

    function createNFT(
        address _address,
        uint256 _type
    ) external whenNotPaused onlyRole(MANAGERMENT_ROLE) {
        uint256 tokenId = _createNFT(_address);
        emit createGeneralHash(_address, tokenId, _type);
    }

    /*
     * mint a General hash
     * @param _address: owner of NFT
     */

    function mint(
        address _address
    ) external onlyRole(MANAGERMENT_ROLE) returns (uint256) {
        return _createNFT(_address);
    }

    /*
     * burn a General hash
     * @param _tokenId: tokenId burn
     */
    function burn(
        uint256 _tokenId
    ) external whenNotPaused onlyRole(MANAGERMENT_ROLE) {
        _burn(_tokenId);
    }
}