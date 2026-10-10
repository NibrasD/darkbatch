// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Minimal ERC-20 interface used by DarkBatchQuoteEscrow.
interface IERC20Quote {
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 value) external returns (bool);
    function transferFrom(address from, address to, uint256 value) external returns (bool);
}

/// @title DarkBatchQuoteEscrow
/// @notice Locks the USDC leg for an already-matched DarkBatch FBA epoch.
///
/// The contract does NOT verify Zcash consensus. The configured oracle is a trust boundary:
/// it may attest only after independently querying a synced Zebra node for a confirmed ZEC TXID.
/// No escrow should hold real funds until the contract and oracle integration are audited.
contract DarkBatchQuoteEscrow {
    uint8 public constant STATUS_NONE = 0;
    uint8 public constant STATUS_OPEN = 1;
    uint8 public constant STATUS_FUNDED = 2;
    uint8 public constant STATUS_ZEC_CONFIRMED = 3;
    uint8 public constant STATUS_RELEASED = 4;
    uint8 public constant STATUS_REFUNDABLE = 5;
    uint8 public constant STATUS_REFUNDED = 6;

    IERC20Quote public immutable usdc;
    address public immutable operator;
    address public immutable oracle;

    struct Batch {
        uint8 status;
        bytes32 planHash;
        uint256 buyerTotalMicro;
        uint256 sellerTotalMicro;
        uint256 buyerCount;
        uint256 paidBuyerCount;
        uint256 refundedBuyerCount;
        uint256 deadline;
        bytes32 zecTxid;
        bytes32 zecBlockHash;
        bytes32 escrowDataHash;
    }

    mapping(bytes32 => Batch) private batches;
    mapping(bytes32 => address[]) private buyers;
    mapping(bytes32 => uint256[]) private buyerAmounts;
    mapping(bytes32 => bool[]) private buyerPaid;
    mapping(bytes32 => bool[]) private buyerRefunded;
    mapping(bytes32 => address[]) private sellers;
    mapping(bytes32 => uint256[]) private sellerAmounts;

    uint256 private entered = 1;

    error Unauthorized();
    error InvalidBatch();
    error InvalidStatus(uint8 status);
    error InvalidAddress();
    error InvalidAmounts();
    error InvalidOrdering();
    error DeadlinePassed();
    error DeadlineNotPassed();
    error AlreadyProcessed();
    error TransferFailed();
    error ZecNotConfirmed();
    error ZeroZecReference();
    error BatchNotFound();

    event BatchOpened(bytes32 indexed batchId, bytes32 indexed planHash, bytes32 escrowDataHash, uint256 buyerTotalMicro, uint256 deadline);
    event BuyerFunded(bytes32 indexed batchId, uint256 indexed buyerIndex, address buyer, uint256 amountMicro);
    event BatchFullyFunded(bytes32 indexed batchId, bytes32 planHash);
    event ZecConfirmed(bytes32 indexed batchId, bytes32 indexed zecTxid, bytes32 zecBlockHash);
    event BatchReleased(bytes32 indexed batchId, bytes32 indexed zecTxid);
    event BatchMarkedRefundable(bytes32 indexed batchId);
    event BuyerRefunded(bytes32 indexed batchId, uint256 indexed buyerIndex, address buyer, uint256 amountMicro);
    event BatchRefunded(bytes32 indexed batchId);

    modifier onlyOperator() {
        if (msg.sender != operator) revert Unauthorized();
        _;
    }

    modifier onlyOracle() {
        if (msg.sender != oracle) revert Unauthorized();
        _;
    }

    modifier nonReentrant() {
        if (entered != 1) revert Unauthorized();
        entered = 2;
        _;
        entered = 1;
    }

    constructor(IERC20Quote usdc_, address operator_, address oracle_) {
        if (address(usdc_) == address(0) || operator_ == address(0) || oracle_ == address(0)) {
            revert InvalidAddress();
        }
        usdc = usdc_;
        operator = operator_;
        oracle = oracle_;
    }

    /// @notice Creates a fixed, committed buyer-deposit/seller-payout batch.
    /// Arrays must be sorted by (numeric address, amount), matching quote_escrow.py.
    function openBatch(
        bytes32 batchId,
        bytes32 planHash,
        address[] calldata buyerAddresses,
        uint256[] calldata buyerAmounts,
        address[] calldata sellerAddresses,
        uint256[] calldata sellerAmounts,
        uint256 deadline
    ) external onlyOperator {
        if (
            batchId == bytes32(0) ||
            planHash == bytes32(0) ||
            batches[batchId].status != STATUS_NONE ||
            deadline <= block.timestamp ||
            buyerAddresses.length == 0 ||
            sellerAddresses.length == 0 ||
            buyerAddresses.length != buyerAmounts.length ||
            sellerAddresses.length != sellerAmounts.length
        ) revert InvalidBatch();

        uint256 buyerTotal;
        address priorAddress;
        uint256 priorAmount;
        for (uint256 i; i < buyerAddresses.length; ++i) {
            address recipient = buyerAddresses[i];
            uint256 amount = buyerAmounts[i];
            if (recipient == address(0) || amount == 0) revert InvalidAmounts();
            if (
                i > 0 &&
                (uint160(recipient) < uint160(priorAddress) ||
                 (recipient == priorAddress && amount < priorAmount))
            ) revert InvalidOrdering();
            priorAddress = recipient;
            priorAmount = amount;
            buyerTotal += amount;
        }

        uint256 sellerTotal;
        priorAddress = address(0);
        priorAmount = 0;
        for (uint256 i; i < sellerAddresses.length; ++i) {
            address recipient = sellerAddresses[i];
            uint256 amount = sellerAmounts[i];
            if (recipient == address(0) || amount == 0) revert InvalidAmounts();
            if (
                i > 0 &&
                (uint160(recipient) < uint160(priorAddress) ||
                 (recipient == priorAddress && amount < priorAmount))
            ) revert InvalidOrdering();
            priorAddress = recipient;
            priorAmount = amount;
            sellerTotal += amount;
        }
        if (buyerTotal == 0 || buyerTotal != sellerTotal) revert InvalidAmounts();

        Batch storage b = batches[batchId];
        b.status = STATUS_OPEN;
        b.planHash = planHash;
        b.buyerTotalMicro = buyerTotal;
        b.sellerTotalMicro = sellerTotal;
        b.buyerCount = buyerAddresses.length;
        b.deadline = deadline;
        b.escrowDataHash = keccak256(
            abi.encode(buyerAddresses, buyerAmounts, sellerAddresses, sellerAmounts)
        );

        for (uint256 i; i < buyerAddresses.length; ++i) {
            buyers[batchId].push(buyerAddresses[i]);
            buyerAmounts[batchId].push(buyerAmounts[i]);
            buyerPaid[batchId].push(false);
            buyerRefunded[batchId].push(false);
        }
        for (uint256 i; i < sellerAddresses.length; ++i) {
            sellers[batchId].push(sellerAddresses[i]);
            sellerAmounts[batchId].push(sellerAmounts[i]);
        }

        emit BatchOpened(batchId, planHash, b.escrowDataHash, buyerTotal, deadline);
    }

    /// @notice Locks exactly the committed USDC amount for one buyer line.
    function fundBuyer(bytes32 batchId, uint256 buyerIndex) external nonReentrant {
        Batch storage b = batches[batchId];
        if (b.status != STATUS_OPEN) revert InvalidStatus(b.status);
        if (block.timestamp > b.deadline) revert DeadlinePassed();
        if (buyerIndex >= buyers[batchId].length) revert InvalidBatch();
        if (buyers[batchId][buyerIndex] != msg.sender) revert Unauthorized();
        if (buyerPaid[batchId][buyerIndex]) revert AlreadyProcessed();

        uint256 amount = buyerAmounts[batchId][buyerIndex];
        uint256 beforeBalance = usdc.balanceOf(address(this));
        buyerPaid[batchId][buyerIndex] = true;
        b.paidBuyerCount += 1;
        if (!usdc.transferFrom(msg.sender, address(this), amount)) revert TransferFailed();
        uint256 afterBalance = usdc.balanceOf(address(this));
        if (afterBalance < beforeBalance || afterBalance - beforeBalance != amount) revert TransferFailed();

        emit BuyerFunded(batchId, buyerIndex, msg.sender, amount);
        if (b.paidBuyerCount == b.buyerCount) {
            b.status = STATUS_FUNDED;
            emit BatchFullyFunded(batchId, b.planHash);
        }
    }

    /// @notice Oracle attestation after independently verifying the named TXID is confirmed by Zebra.
    function markZecConfirmed(bytes32 batchId, bytes32 zecTxid, bytes32 zecBlockHash) external onlyOracle {
        Batch storage b = batches[batchId];
        if (b.status != STATUS_FUNDED) revert InvalidStatus(b.status);
        if (zecTxid == bytes32(0) || zecBlockHash == bytes32(0)) revert ZeroZecReference();
        b.status = STATUS_ZEC_CONFIRMED;
        b.zecTxid = zecTxid;
        b.zecBlockHash = zecBlockHash;
        emit ZecConfirmed(batchId, zecTxid, zecBlockHash);
    }

    /// @notice Releases seller payouts only after the oracle attested a confirmed ZEC transaction.
    function releaseBatch(bytes32 batchId) external nonReentrant {
        Batch storage b = batches[batchId];
        if (b.status != STATUS_ZEC_CONFIRMED) revert InvalidStatus(b.status);
        if (b.zecTxid == bytes32(0) || b.zecBlockHash == bytes32(0)) revert ZecNotConfirmed();
        // Set the final state before external token calls; any failed transfer reverts atomically.
        b.status = STATUS_RELEASED;
        for (uint256 i; i < sellers[batchId].length; ++i) {
            if (!usdc.transfer(sellers[batchId][i], sellerAmounts[batchId][i])) revert TransferFailed();
        }
        emit BatchReleased(batchId, b.zecTxid);
    }

    /// @notice Oracle attestation that the ZEC transaction expired/unconfirmed; buyers may reclaim deposits.
    /// @dev The contract cannot establish Zcash non-inclusion itself. This is an explicit oracle trust boundary.
    function markRefundable(bytes32 batchId) external onlyOracle {
        Batch storage b = batches[batchId];
        if (b.status != STATUS_OPEN && b.status != STATUS_FUNDED) revert InvalidStatus(b.status);
        if (block.timestamp <= b.deadline) revert DeadlineNotPassed();
        if (b.zecTxid != bytes32(0)) revert ZecNotConfirmed();
        b.status = STATUS_REFUNDABLE;
        emit BatchMarkedRefundable(batchId);
        if (b.paidBuyerCount == 0) {
            b.status = STATUS_REFUNDED;
            emit BatchRefunded(batchId);
        }
    }

    function refundBuyer(bytes32 batchId, uint256 buyerIndex) external nonReentrant {
        Batch storage b = batches[batchId];
        if (b.status != STATUS_REFUNDABLE) revert InvalidStatus(b.status);
        if (buyerIndex >= buyers[batchId].length) revert InvalidBatch();
        if (buyers[batchId][buyerIndex] != msg.sender) revert Unauthorized();
        if (!buyerPaid[batchId][buyerIndex] || buyerRefunded[batchId][buyerIndex]) revert AlreadyProcessed();

        uint256 amount = buyerAmounts[batchId][buyerIndex];
        buyerRefunded[batchId][buyerIndex] = true;
        b.refundedBuyerCount += 1;
        if (!usdc.transfer(msg.sender, amount)) revert TransferFailed();
        emit BuyerRefunded(batchId, buyerIndex, msg.sender, amount);
        if (b.refundedBuyerCount == b.paidBuyerCount) {
            b.status = STATUS_REFUNDED;
            emit BatchRefunded(batchId);
        }
    }

    /// @return status NONE=0 OPEN=1 FUNDED=2 ZEC_CONFIRMED=3 RELEASED=4 REFUNDABLE=5 REFUNDED=6.
    /// The first ten words preserve the Python reader's established layout; escrowDataHash is word 11.
    function getBatchStatus(bytes32 batchId)
        external view
        returns (
            uint8 status,
            bytes32 planHash,
            uint256 buyerTotalMicro,
            uint256 sellerTotalMicro,
            uint256 buyerCount,
            uint256 paidBuyerCount,
            uint256 deadline,
            address tokenAddress,
            bytes32 zecTxid,
            bytes32 zecBlockHash,
            bytes32 escrowDataHash
        )
    {
        Batch storage b = batches[batchId];
        return (
            b.status,
            b.planHash,
            b.buyerTotalMicro,
            b.sellerTotalMicro,
            b.buyerCount,
            b.paidBuyerCount,
            b.deadline,
            address(usdc),
            b.zecTxid,
            b.zecBlockHash,
            b.escrowDataHash
        );
    }

    function buyerAt(bytes32 batchId, uint256 index) external view returns (address recipient, uint256 amount, bool paid, bool refunded) {
        if (index >= buyers[batchId].length) revert InvalidBatch();
        return (buyers[batchId][index], buyerAmounts[batchId][index], buyerPaid[batchId][index], buyerRefunded[batchId][index]);
    }

    function sellerAt(bytes32 batchId, uint256 index) external view returns (address recipient, uint256 amount) {
        if (index >= sellers[batchId].length) revert InvalidBatch();
        return (sellers[batchId][index], sellerAmounts[batchId][index]);
    }
}
