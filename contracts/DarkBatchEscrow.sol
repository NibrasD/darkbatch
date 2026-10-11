// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./IERC20.sol";
import "./Ownable.sol";
import "./ReentrancyGuard.sol";

/**
 * @title DarkBatchEscrow
 * @author DarkBatch Protocol Team
 * @notice Confidential Frequent Batch Auction (FBA) Cross-Chain Settlement Escrow for USDC / Shielded ZEC.
 * @dev Locks USDC deposits per batchId, releases funds to payee upon cryptographic oracle attestation
 *      of valid Zcash NU6.3 / ZIP 229 settlement transaction inclusion, or refunds to depositor if timeout expires.
 */
contract DarkBatchEscrow is Ownable, ReentrancyGuard {
    /// @notice Status tracking for individual batch escrows to prevent double-release or unauthorized refund.
    enum EscrowStatus {
        NONE,       // 0: Uninitialized
        DEPOSITED,  // 1: Funds locked and waiting for settlement attestation
        RELEASED,   // 2: Settled and paid out to seller
        REFUNDED    // 3: Expired and refunded back to depositor
    }

    /// @notice Escrow record stored for each batch settlement.
    struct EscrowRecord {
        address depositor;
        uint256 amount;
        uint256 batchId;
        uint256 deadline;
        EscrowStatus status;
    }

    /// @notice ERC-20 USDC token contract used for settling the quote asset.
    IERC20 public immutable usdc;

    /// @notice Authorized DarkBatch settlement oracle responsible for signing cross-chain Zcash inclusion proofs.
    address public oracle;

    /// @notice Mapping from batchId => EscrowRecord.
    mapping(uint256 => EscrowRecord) public escrows;

    // --- Custom Errors ---
    error ZeroAddress();
    error InvalidAmount();
    error InvalidDeadline();
    error EscrowAlreadyExists(uint256 batchId);
    error EscrowNotFound(uint256 batchId);
    error EscrowNotDeposited(uint256 batchId, EscrowStatus currentStatus);
    error DeadlineNotPassed(uint256 deadline, uint256 currentTimestamp);
    error InvalidReleaseAmount(uint256 requestedAmount, uint256 depositedAmount);
    error NotAuthorizedOracle(address caller, address expectedOracle);
    error InvalidSignatureLength();
    error InvalidSignatureV();
    error InvalidOracleSignature();
    error TokenTransferFailed();

    // --- Events ---
    /**
     * @notice Emitted when a participant locks USDC in escrow for a designated batch.
     * @param batchId The unique identifier of the clearing epoch / batch auction.
     * @param depositor The account funding the escrow.
     * @param amount The quantity of USDC locked (in atomic units).
     * @param deadline The unix timestamp after which refund may be triggered if not settled.
     */
    event EscrowDeposited(
        uint256 indexed batchId,
        address indexed depositor,
        uint256 amount,
        uint256 deadline
    );

    /**
     * @notice Emitted when the escrowed USDC is successfully released to the payee.
     * @param batchId The unique identifier of the batch auction.
     * @param payee The recipient receiving the USDC payment.
     * @param amount The released USDC amount.
     * @param zcashTxId The verified Zcash transaction identifier (ZIP 244 hierarchical hash).
     */
    event EscrowReleased(
        uint256 indexed batchId,
        address indexed payee,
        uint256 amount,
        bytes32 indexed zcashTxId
    );

    /**
     * @notice Emitted when an expired escrow is refunded back to the depositor.
     * @param batchId The unique identifier of the batch auction.
     * @param depositor The recipient receiving the refunded USDC.
     * @param amount The refunded USDC amount.
     */
    event EscrowRefunded(
        uint256 indexed batchId,
        address indexed depositor,
        uint256 amount
    );

    /**
     * @notice Emitted when the authorized oracle address is updated by the owner.
     * @param previousOracle The previous oracle address.
     * @param newOracle The new oracle address.
     */
    event OracleUpdated(
        address indexed previousOracle,
        address indexed newOracle
    );

    /// @notice Restricts function invocation to the authorized oracle account.
    modifier onlyOracle() {
        if (msg.sender != oracle) {
            revert NotAuthorizedOracle(msg.sender, oracle);
        }
        _;
    }

    /**
     * @notice Deploys the DarkBatchEscrow contract.
     * @param _usdc Address of the USDC ERC-20 token contract.
     * @param _initialOracle Initial authorized DarkBatch settlement oracle address.
     */
    constructor(address _usdc, address _initialOracle) Ownable(msg.sender) {
        if (_usdc == address(0) || _initialOracle == address(0)) {
            revert ZeroAddress();
        }
        usdc = IERC20(_usdc);
        oracle = _initialOracle;
        emit OracleUpdated(address(0), _initialOracle);
    }

    /**
     * @notice Updates the authorized settlement oracle address.
     * @dev Only callable by the contract owner.
     * @param _newOracle The new oracle address.
     */
    function setOracle(address _newOracle) external onlyOwner {
        if (_newOracle == address(0)) {
            revert ZeroAddress();
        }
        address previousOracle = oracle;
        oracle = _newOracle;
        emit OracleUpdated(previousOracle, _newOracle);
    }

    /**
     * @notice Locks USDC in escrow for a designated batchId. Requires prior ERC-20 `approve`.
     * @param batchId The unique identifier of the batch auction.
     * @param amount The quantity of USDC to deposit (base units, e.g. 6 decimals).
     * @param deadline Unix timestamp after which funds can be refunded if unexecuted.
     */
    function depositEscrow(
        uint256 batchId,
        uint256 amount,
        uint256 deadline
    ) external nonReentrant {
        if (batchId == 0) revert InvalidAmount();
        if (amount == 0) revert InvalidAmount();
        if (deadline <= block.timestamp) revert InvalidDeadline();

        EscrowRecord storage record = escrows[batchId];
        if (record.status != EscrowStatus.NONE) {
            revert EscrowAlreadyExists(batchId);
        }

        record.depositor = msg.sender;
        record.amount = amount;
        record.batchId = batchId;
        record.deadline = deadline;
        record.status = EscrowStatus.DEPOSITED;

        emit EscrowDeposited(batchId, msg.sender, amount, deadline);

        bool success = usdc.transferFrom(msg.sender, address(this), amount);
        if (!success) {
            revert TokenTransferFailed();
        }
    }

    /**
     * @notice Releases escrowed USDC to the seller after oracle attestation of Zcash settlement.
     * @dev Only callable by the authorized oracle. Verifies EIP-191 cryptographic signature.
     *      If partial fill occurred (amount < record.amount), remaining funds are refunded to depositor.
     * @param batchId The batch auction identifier.
     * @param payee The recipient seller EVM address.
     * @param amount The settled USDC amount to deliver to payee.
     * @param zcashTxId The ZIP 244 32-byte hierarchical transaction ID from Zcash NU6.3.
     * @param oracleSignature The 65-byte ECDSA signature signed by the authorized oracle.
     */
    function releaseEscrow(
        uint256 batchId,
        address payee,
        uint256 amount,
        bytes32 zcashTxId,
        bytes calldata oracleSignature
    ) external onlyOracle nonReentrant {
        EscrowRecord storage record = escrows[batchId];
        if (record.status != EscrowStatus.DEPOSITED) {
            revert EscrowNotDeposited(batchId, record.status);
        }
        if (payee == address(0)) {
            revert ZeroAddress();
        }
        if (amount == 0 || amount > record.amount) {
            revert InvalidReleaseAmount(amount, record.amount);
        }

        // Verify cryptographic attestation from the authorized oracle
        bytes32 ethSignedMessageHash = getEthSignedMessageHash(batchId, payee, amount, zcashTxId);
        address recovered = _recoverSigner(ethSignedMessageHash, oracleSignature);
        if (recovered != oracle) {
            revert InvalidOracleSignature();
        }

        uint256 totalLocked = record.amount;
        record.status = EscrowStatus.RELEASED;

        emit EscrowReleased(batchId, payee, amount, zcashTxId);

        // Transfer released USDC to payee
        bool success = usdc.transfer(payee, amount);
        if (!success) {
            revert TokenTransferFailed();
        }

        // Return surplus back to depositor in case of price improvement / rationing
        if (totalLocked > amount) {
            uint256 surplus = totalLocked - amount;
            bool surplusSuccess = usdc.transfer(record.depositor, surplus);
            if (!surplusSuccess) {
                revert TokenTransferFailed();
            }
        }
    }

    /**
     * @notice Refunds locked USDC back to the depositor once the deadline has passed.
     * @dev Anyone can trigger this after timeout expires.
     * @param batchId The batch auction identifier.
     */
    function refundEscrow(uint256 batchId) external nonReentrant {
        EscrowRecord storage record = escrows[batchId];
        if (record.status != EscrowStatus.DEPOSITED) {
            revert EscrowNotDeposited(batchId, record.status);
        }
        if (block.timestamp <= record.deadline) {
            revert DeadlineNotPassed(record.deadline, block.timestamp);
        }

        uint256 refundAmount = record.amount;
        address depositor = record.depositor;
        record.status = EscrowStatus.REFUNDED;

        emit EscrowRefunded(batchId, depositor, refundAmount);

        bool success = usdc.transfer(depositor, refundAmount);
        if (!success) {
            revert TokenTransferFailed();
        }
    }

    /**
     * @notice Computes canonical digest to be signed by the settlement oracle.
     * @param batchId The batch ID.
     * @param payee Recipient seller address.
     * @param amount The released USDC amount.
     * @param zcashTxId The verified Zcash transaction ID.
     */
    function getMessageHash(
        uint256 batchId,
        address payee,
        uint256 amount,
        bytes32 zcashTxId
    ) public view returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                batchId,
                payee,
                amount,
                zcashTxId,
                address(this),
                block.chainid
            )
        );
    }

    /**
     * @notice Computes EIP-191 prefixed digest for the oracle attestation.
     */
    function getEthSignedMessageHash(
        uint256 batchId,
        address payee,
        uint256 amount,
        bytes32 zcashTxId
    ) public view returns (bytes32) {
        bytes32 messageHash = getMessageHash(batchId, payee, amount, zcashTxId);
        return keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", messageHash)
        );
    }

    /**
     * @notice Returns full escrow record details for a batch.
     * @param batchId The batch auction identifier.
     */
    function getEscrow(uint256 batchId) external view returns (EscrowRecord memory) {
        return escrows[batchId];
    }

    /**
     * @dev Recovers signer address from 65-byte ECDSA signature.
     */
    function _recoverSigner(
        bytes32 ethSignedMessageHash,
        bytes calldata signature
    ) internal pure returns (address) {
        if (signature.length != 65) {
            revert InvalidSignatureLength();
        }

        bytes32 r;
        bytes32 s;
        uint8 v;

        assembly {
            r := calldataload(signature.offset)
            s := calldataload(add(signature.offset, 32))
            v := byte(0, calldataload(add(signature.offset, 64)))
        }

        if (v < 27) {
            v += 27;
        }
        if (v != 27 && v != 28) {
            revert InvalidSignatureV();
        }

        address signer = ecrecover(ethSignedMessageHash, v, r, s);
        if (signer == address(0)) {
            revert InvalidOracleSignature();
        }
        return signer;
    }
}
