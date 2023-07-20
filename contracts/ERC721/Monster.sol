// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import "./Monster/MonsterCore.sol";

contract Monster is MonsterCore {
    // Validator
    address private validator;
    // Status signature
    mapping(bytes => bool) public _isSigned;

    // Set new season
    function setNewSeason() external onlyRole(MANAGEMENT_ROLE) {
        season++;
    }

    // Set fee mint Monster
    function initSetCostOfType(
        TypeMint _type,
        uint256[] memory cost
    ) external onlyRole(MANAGEMENT_ROLE) {
        if (_type == TypeMint.GENERAL_HASH) {
            costOfGeneral = cost;
        } else if (_type == TypeMint.GENESIS_HASH) {
            costOfGenesis = cost;
        } else if (_type == TypeMint.EXTERNAL_NFT) {
            costOfExternal = cost;
        } else if (_type == TypeMint.HASH_CHIP_NFT) {
            costOfHashChip = cost;
        } else {
            revert("Monster:::MonsterCore::setCostOfType: Unsupported type");
        }
    }

    // Set limit mint Monster
    function initSetLimitOfType(
        TypeMint _type,
        uint256 limit
    ) external onlyRole(MANAGEMENT_ROLE) {
        if (_type == TypeMint.GENERAL_HASH) {
            limitGeneral = limit;
        } else if (_type == TypeMint.GENESIS_HASH) {
            limitGenesis = limit;
        } else if (_type == TypeMint.EXTERNAL_NFT) {
            limitExternal = limit;
        } else if (_type == TypeMint.HASH_CHIP_NFT) {
            limitHashChip = limit;
        } else {
            revert("Monster:::MonsterCore::setLimitOfType: Unsupported type");
        }
    }

    // Set address Monster Treasury
    function initSetTreasuryAdress(
        address _address
    ) external onlyRole(MANAGEMENT_ROLE) {
        _treasuryAddress = payable(_address);
    }
    function initSetValidator(
        address _address
    ) external whenNotPaused onlyOwner {
        validator = _address;
    }

    /*
     * Create a Monster by type
     * @param _type: address of owner
     * @param _tokenId: first tokenId fusion
     * @param _isOAS: last tokenId fusion
     * @param _cost: list fusion item, if dont using fusion item => _itemId = [0]
     * @param _deadline: number of fusion item
     */
    function mintMonster(
        TypeMint _type,
        uint256 _tokenId,
        bool _isOAS,
        uint256 _cost,
        uint256 _deadline,
        bytes calldata _sig
    ) external nonReentrant payable whenNotPaused {
        require(
            _deadline > block.timestamp,
            "Monster:::Monster::mintMonster: Deadline exceeded"
        );
        require(
            !_isSigned[_sig],
            "Monster:::Monster::mintMonster: Signature used"
        );
        
        address signer = recoverOAS(
            _type,
            _cost,
            _tokenId,
            block.chainid,
            _deadline,
            _sig
        );
        require(
            signer == validator,
            "Monster:::Monster::mintMonster: Validator fail signature"
        );
        uint256 tokenId = _mintMonster(_type, _tokenId, _isOAS, _cost);
        emit createNFTMonster(msg.sender, tokenId, _type);
    }

    /*
     * Create a Monster by type Free
     */
    function mintMonsterFree() external nonReentrant whenNotPaused {
        uint256 tokenId = _fromFreeNFT();
        emit createNFTMonster(msg.sender, tokenId, TypeMint.FREE);
    }

    /*
     * Create a Monster by type Free
     */
    function mintMonsterFromRegeneration(uint256 _tokenId) external nonReentrant whenNotPaused {
        uint256 tokenId = _fromRegenerationNFT(_tokenId);
        emit createNFTMonster(msg.sender, tokenId, TypeMint.REGENERATION_ITEM);
    }

    /*
     * fusion a Monster
     * @param _address: address of owner
     * @param _firstTokenId: first tokenId fusion
     * @param _lastTokenId: last tokenId fusion
     * @param _itemId: list fusion item, if dont using fusion item => _itemId = [0]
     * @param _amount: number of fusion item
     */
    function fusionMonsterNFT(
        address _owner,
        uint256 _firstTokenId,
        uint256 _lastTokenId,
        uint256[] memory _itemId,
        uint256[] memory _amount
    ) external nonReentrant whenNotPaused {
        uint256 tokenId = _fusionMonsterNFT(
            _owner,
            _firstTokenId,
            _lastTokenId,
            _itemId,
            _amount
        );
        emit fusionMultipleMonster(
            _owner,
            tokenId,
            _firstTokenId,
            _lastTokenId
        );
    }

    /*
     * Create monster from fusion genersis hash
     * @param _owner: address of owner
     * @param _firstId: first tokenId fusion
     * @param _lastId: last tokenId fusion
     * @param _itemId: list fusion item, if dont using fusion item => _itemId = [0]
     * @param _amount: number of fusion item
     */
    function fusionGenesisHash(
        address _owner,
        uint256 _firstId,
        uint256 _lastId,
        uint256[] memory _itemId,
        uint256[] memory _amount
    ) external nonReentrant whenNotPaused {
        uint256 tokenId = _fusionGenesisHash(
            _owner,
            _firstId,
            _lastId,
            _itemId,
            _amount
        );
        emit fusionGenesisHashNFT(_owner, _firstId, _lastId, tokenId);
    }

    /*
     * Create monster from fusion general hash
     * @param _owner: address of owner
     * @param _firstId: first tokenId fusion
     * @param _lastId: last tokenId fusion
     * @param _itemId: list fusion item, if dont using fusion item => _itemId = [0]
     * @param _amount: number of fusion item
     */
    function fusionGeneralHash(
        address _owner,
        uint256 _firstId,
        uint256 _lastId,
        uint256[] memory _itemId,
        uint256[] memory _amount
    ) external nonReentrant whenNotPaused {
        uint256 tokenId = _fusionGeneralHash(
            _owner,
            _firstId,
            _lastId,
            _itemId,
            _amount
        );
        emit fusionGeneralHashNFT(_owner, _firstId, _lastId, tokenId);
    }

    /*
     * Create monster from fusion genesis + general hash
     * @param _owner: address of owner
     * @param _genersisId: genesis tokenId fusion
     * @param _generalId: general tokenId fusion
     * @param _itemId: list fusion item, if dont using fusion item => _itemId = [0]
     * @param _amount: number of fusion item
     */
    function fusionMultipleHash(
        address _owner,
        uint256 _genesisId,
        uint256 _generalId,
        uint256[] memory _itemId,
        uint256[] memory _amount
    ) external nonReentrant whenNotPaused {
        uint256 tokenId = _fusionMultipleHash(
            _owner,
            _genesisId,
            _generalId,
            _itemId,
            _amount
        );
        emit fusionMultipleHashNFT(_owner, _genesisId, _generalId, tokenId);
    }

    /*
     * Refresh Times Of Regeneration
     * @param _type: address of owner
     * @param _tokenId: first tokenId fusion
     * @param _isOAS: last tokenId fusion
     * @param _cost: list fusion item, if dont using fusion item => _itemId = [0]
     * @param _deadline: number of fusion item
     */
    function refreshTimesOfRegeneration(
        TypeMint _type,
        uint256 _tokenId,
        bool _isOAS,
        uint256 _cost,
        uint256 _deadline,
        bytes calldata _sig
    ) external nonReentrant payable whenNotPaused {
        require(
            _deadline > block.timestamp,
            "Monster:::Monster::mintMonster: Deadline exceeded"
        );
        require(
            !_isSigned[_sig],
            "Monster:::Monster::mintMonster: Signature used"
        );
        address signer = recoverOAS(
            _type,
            _cost,
            _tokenId,
            block.chainid,
            _deadline,
            _sig
        );
        require(
            signer == validator,
            "Monster:::Monster::mintMonster: Validator fail signature"
        );
        _refreshTimesOfRegeneration(_type, _tokenId, _isOAS, _cost);
    }
    /*
     * get Fee mint Monster by TyMint & tokenId
     * @param _type: TypeMint
     * @param _tokenId: tokenId
     */
    function getFeeOfTokenId(
        TypeMint _type,
        uint256 _tokenId
    ) external view whenNotPaused returns (uint256 fee) {
        if (_type == TypeMint.EXTERNAL_NFT) {
            uint256 countRegeneration = _numberOfRegenerations[season][
                TypeMint.EXTERNAL_NFT
            ][_tokenId];
            fee = costOfExternal[countRegeneration];
        } else if (_type == TypeMint.GENESIS_HASH) {
            uint256 countRegeneration = _numberOfRegenerations[season][
                TypeMint.GENESIS_HASH
            ][_tokenId];
            fee = costOfExternal[countRegeneration];
        } else if (_type == TypeMint.GENERAL_HASH) {
            uint256 countRegeneration = _numberOfRegenerations[season][
                TypeMint.GENERAL_HASH
            ][_tokenId];
            fee = costOfExternal[countRegeneration];
        } else if (_type == TypeMint.HASH_CHIP_NFT) {
            uint256 countRegeneration = _numberOfRegenerations[season][
                TypeMint.HASH_CHIP_NFT
            ][_tokenId];
            fee = costOfExternal[countRegeneration];
        } else {
            revert("Monster:::MonsterCore::getFeeOfTokenId: Unsupported type");
        }
    }
}
