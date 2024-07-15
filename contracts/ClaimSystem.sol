//SPDX-License-Identifier: MIT
pragma solidity ^0.8.1;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract ClaimSystem is AccessControl, Ownable {
    bytes32 public constant MANAGEMENT_ROLE = keccak256("MANAGEMENT_ROLE");
    IERC20 tokenBase;
    address public validator;
    uint256 public sessionId;

    struct UserInfor {
        uint256 total;
        uint256 claimed;
    }

    event ChangeValidatorAddress(address validatorAddress);
    event ClaimToken(
        address to,
        uint256 amount,
        address tokenAddress,
        bytes signature
    );

    mapping(bytes => bool) public _isSignedClaim;
    mapping(address => UserInfor) public userInfor;
    mapping(uint256 => mapping(address => mapping(uint256 => bool)))
        public epochClaimed;

    constructor(IERC20 _tokenBase) {
        _setRoleAdmin(MANAGEMENT_ROLE, MANAGEMENT_ROLE);
        _setupRole(MANAGEMENT_ROLE, _msgSender());
        validator = _msgSender();
        tokenBase = _tokenBase;
        sessionId = 1;
    }

    /**
     * @dev Change validator address
     * @param _validatorAddress  new validator address
     */
    function changeValidator(
        address _validatorAddress
    ) external onlyRole(MANAGEMENT_ROLE) {
        // verify new exchange value
        validator = _validatorAddress;
        emit ChangeValidatorAddress(_validatorAddress);
    }

    /**
     * @dev Change Session
     * @param _sessionId  New Session ID
     */
    function setSession(uint256 _sessionId) external onlyRole(MANAGEMENT_ROLE) {
        sessionId = _sessionId;
    }

    /**
     * @dev Claim token
     * @notice Addresses in the whitelist can claim rewards when the SALD price reaches the target
     * @param epochs Epochs of the SALD marketcap
     * @param _amount Amount of reward that can be claimed
     * @param deadline Deadline of the signature
     * @param sig Signature by admin
     */
    function claimToken(
        uint256[] memory _epochs,
        uint256 _amount,
        uint256 deadline,
        bytes calldata sig
    ) external {
        require(deadline > block.timestamp, "Deadline exceeded");
        for (uint256 index = 0; index < _epochs.length; index++) {
            require(
                !epochClaimed[sessionId][_msgSender()][_epochs[index]],
                "Epoch marketcap claimed"
            );
        }
        require(!_isSignedClaim[sig], "Signature used");

        address signer = recoverClaim(
            _epochs,
            block.chainid,
            _msgSender(),
            _amount,
            deadline,
            sig
        );
        require(signer == validator, "Validator fail signature");

        require(
            tokenBase.balanceOf(address(this)) >= _amount,
            "Insufficient token funds"
        );
        userInfor[_msgSender()].claimed += _amount;
        // transfer token to user
        tokenBase.transfer(_msgSender(), _amount);
        // set deadline map msgSender
        _isSignedClaim[sig] = true;
        for (uint256 index = 0; index < _epochs.length; index++) {
            epochClaimed[sessionId][_msgSender()][_epochs[index]] = true;
        }

        emit ClaimToken(_msgSender(), _amount, address(tokenBase), sig);
    }

    /**
     * @dev Decode data claim
     * @notice Decode data claim by admin. Then recover by admin
     * @param epochs Epochs of the SALD marketcap
     * @param chainId ChainId of the blockchain network - Ethereum
     * @param receiver Address to claim
     * @param amount Amount of reward to claim
     * @param deadline Deadline of the signature
     * @param sig Signature by admin
     */
    function recoverClaim(
        uint256[] memory epochs,
        uint256 chainId,
        address receiver,
        uint256 amount,
        uint256 deadline,
        bytes calldata sig
    ) public pure returns (address) {
        return
            ECDSA.recover(
                ECDSA.toEthSignedMessageHash(
                    encodeClaim(epochs, chainId, receiver, amount, deadline)
                ),
                sig
            );
    }

    /**
     * @dev Encode data claim
     * @notice Encode data claim by admin. Then sign the message by admin
     * @param epochs Epochs of the SALD marketcap
     * @param chainId ChainId of the blockchain network - Ethereum
     * @param receiver Address to claim
     * @param deadline Deadline of the signature
     */
    function encodeClaim(
        uint256[] memory epochs,
        uint256 chainId,
        address receiver,
        uint256 amount,
        uint256 deadline
    ) public pure returns (bytes32) {
        bytes memory m = abi.encode(
            epochs,
            chainId,
            receiver,
            amount,
            deadline
        );

        return keccak256(m);
    }

    /**
     * @dev Emergency withdraw token out of this contract
     * @notice only contract owner can call this function, token receiver may difference
     * @param _tokenAddress   token address
     * @param _to   receiver address
     */
    function emergencyWithdraw(
        IERC20 _tokenAddress,
        address _to
    ) external onlyRole(MANAGEMENT_ROLE) {
        // Get token balance
        uint256 balance = _tokenAddress.balanceOf(address(this));

        // Transfer to receiver
        _tokenAddress.transfer(_to, balance);
    }
}
