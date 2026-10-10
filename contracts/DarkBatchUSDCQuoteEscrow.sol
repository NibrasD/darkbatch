// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Holds USDC quote funds for a DarkBatch FBA batch before the ZEC leg is broadcast.
/// @dev A designated settlementOracle must attest to the confirmed Zcash transaction.
///      EVM contracts cannot independently verify Zcash consensus or shielded outputs; this
///      oracle is an explicit trust assumption, not trustless atomic cross-chain settlement.
interface IERC20Quote {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function decimals() external view returns (uint8);
}

contract DarkBatchUSDCQuoteEscrow {
    enum Status {
        NONE,          // 0
        OPEN,          // 1: waiting for all buyer deposits
        FUNDED,        // 2: all USDC has been deposited; ZEC may be broadcast
        ZEC_CONFIRMED, // 3: trusted oracle attested a confirmed ZEC transaction
        RELEASED,      // 4: USDC has been paid to sellers
        REFUNDABLE,    // 5: deadline passed before oracle confirmation
        REFUNDED       // 6: all deposited USDC has been refunded
    }

    struct Batch {
        bytes32 planHash;
        uint256 totalBuyerAmount;
        uint256 totalSellerAmount;
        uint256 buyerCount;
        uint256 paidBuyerCount;
        uint256 refundedBuyerCount;
        uint256 sellerCount;
        uint64 deadline;
        Status status;
        bytes32 zcashTxid;
        bytes32 zcashBlockHash;
    }

    IERC20Quote public immutable usdc;
    address public owner;
    address public coordinator;
    address public settlementOracle;

    mapping(bytes32 => Batch) private batches;
    mapping(bytes32 => mapping(address => uint256)) public buyerDue;
    mapping(bytes32 => mapping(address => uint256)) public buyerPaid;
    mapping(bytes32 => mapping(address => bool)) public buyerRefunded;
    mapping(bytes32 => mapping(address => uint256)) public sellerPayout;
    mapping(bytes32 => mapping(address => bool)) private knownBuyer;
    mapping(bytes32 => mapping(address => bool)) private knownSeller;
    mapping(bytes32 => address[]) private batchBuyers;
    mapping(bytes32 => address[]) private batchSellers;

    event BatchOpened(bytes32 indexed batchId, bytes32 indexed planHash, uint256 totalUSDC, uint64 deadline);
    event BuyerDeposited(bytes32 indexed batchId, address indexed buyer, uint256 amount);
    event BatchFunded(bytes32 indexed batchId, uint256 totalUSDC);
    event ZecSettlementConfirmed(bytes32 indexed batchId, bytes32 indexed zcashTxid, bytes32 zcashBlockHash);
    event USDCReleased(bytes32 indexed batchId, address indexed seller, uint256 amount);
    event BuyerRefunded(bytes32 indexed batchId, address indexed buyer, uint256 amount);
    event BatchRefundable(bytes32 indexed batchId);

    modifier onlyOwner() {
        require(msg.sender == owner, "owner only");
        _;
    }

    modifier onlyCoordinator() {
        require(msg.sender == coordinator, "coordinator only");
        _;
    }

    modifier onlySettlementOracle() {
        require(msg.sender == settlementOracle, "settlement oracle only");
        _;
    }

    constructor(address usdcAddress, address coordinatorAddress, address oracleAddress) {
        require(usdcAddress != address(0), "zero USDC");
        require(coordinatorAddress != address(0), "zero coordinator");
        require(oracleAddress != address(0), "zero oracle");
        require(IERC20Quote(usdcAddress).decimals() == 6, "quote token must use 6 decimals");
        usdc = IERC20Quote(usdcAddress);
        coordinator = coordinatorAddress;
        settlementOracle = oracleAddress;
        owner = msg.sender;
    }

    function setCoordinator(address value) external onlyOwner {
        require(value != address(0), "zero coordinator");
        coordinator = value;
    }

    function setSettlementOracle(address value) external onlyOwner {
        require(value != address(0), "zero oracle");
        settlementOracle = value;
    }

    /// @notice Registers exact buyer obligations and seller payout amounts from a canonical FBA plan.
    /// @dev buyer/seller arrays must be aggregated by EVM address, with no duplicate addresses.
    function openBatch(
        bytes32 batchId,
        bytes32 planHash,
        address[] calldata buyers,
        uint256[] calldata buyerAmounts,
        address[] calldata sellers,
        uint256[] calldata sellerAmounts,
        uint64 deadline
    ) external onlyCoordinator {
        require(batchId != bytes32(0) && planHash != bytes32(0), "zero batch/plan hash");
        require(batches[batchId].status == Status.NONE, "batch already exists");
        require(deadline > block.timestamp, "deadline must be in future");
        require(buyers.length > 0 && buyers.length <= 64, "buyer count out of range");
        require(sellers.length > 0 && sellers.length <= 64, "seller count out of range");
        require(buyers.length == buyerAmounts.length, "buyer arrays mismatch");
        require(sellers.length == sellerAmounts.length, "seller arrays mismatch");

        uint256 totalBuy;
        uint256 totalSell;
        for (uint256 i; i < buyers.length; ++i) {
            address buyer = buyers[i];
            uint256 amount = buyerAmounts[i];
            require(buyer != address(0) && amount > 0, "invalid buyer");
            require(!knownBuyer[batchId][buyer], "duplicate buyer");
            knownBuyer[batchId][buyer] = true;
            buyerDue[batchId][buyer] = amount;
            batchBuyers[batchId].push(buyer);
            totalBuy += amount;
        }

        for (uint256 i; i < sellers.length; ++i) {
            address seller = sellers[i];
            uint256 amount = sellerAmounts[i];
            require(seller != address(0) && amount > 0, "invalid seller payout");
            require(!knownSeller[batchId][seller], "duplicate seller");
            knownSeller[batchId][seller] = true;
            sellerPayout[batchId][seller] = amount;
            batchSellers[batchId].push(seller);
            totalSell += amount;
        }
        require(totalBuy > 0 && totalBuy == totalSell, "USDC quote totals must balance");

        Batch storage batch = batches[batchId];
        batch.planHash = planHash;
        batch.totalBuyerAmount = totalBuy;
        batch.totalSellerAmount = totalSell;
        batch.buyerCount = buyers.length;
        batch.sellerCount = sellers.length;
        batch.deadline = deadline;
        batch.status = Status.OPEN;
        emit BatchOpened(batchId, planHash, totalBuy, deadline);
    }

    /// @notice Each quote payer deposits their full signed obligation; no partial deposits are accepted.
    function deposit(bytes32 batchId) external {
        Batch storage batch = batches[batchId];
        require(batch.status == Status.OPEN, "batch not open");
        uint256 due = buyerDue[batchId][msg.sender];
        require(due > 0 && buyerPaid[batchId][msg.sender] == 0, "not an unpaid buyer");
        require(block.timestamp < batch.deadline, "deposit deadline passed");
        buyerPaid[batchId][msg.sender] = due;
        batch.paidBuyerCount += 1;
        _safeTransferFrom(msg.sender, address(this), due);
        emit BuyerDeposited(batchId, msg.sender, due);
        if (batch.paidBuyerCount == batch.buyerCount) {
            batch.status = Status.FUNDED;
            emit BatchFunded(batchId, batch.totalBuyerAmount);
        }
    }

    /// @notice Trusted relayer calls this only after verifying the actual Zcash transaction and block.
    /// @dev The contract cannot itself validate a Zcash shielded transaction.
    function confirmZecSettlement(
        bytes32 batchId,
        bytes32 zcashTxid,
        bytes32 zcashBlockHash
    ) external onlySettlementOracle {
        Batch storage batch = batches[batchId];
        require(batch.status == Status.FUNDED, "USDC batch not fully funded");
        require(block.timestamp < batch.deadline, "quote settlement deadline passed");
        require(zcashTxid != bytes32(0) && zcashBlockHash != bytes32(0), "missing Zcash confirmation");
        batch.zcashTxid = zcashTxid;
        batch.zcashBlockHash = zcashBlockHash;
        batch.status = Status.ZEC_CONFIRMED;
        emit ZecSettlementConfirmed(batchId, zcashTxid, zcashBlockHash);
    }

    /// @notice Anyone can trigger the final USDC payout only after the oracle-confirmed ZEC leg.
    function releaseBatch(bytes32 batchId) external {
        Batch storage batch = batches[batchId];
        require(batch.status == Status.ZEC_CONFIRMED, "ZEC settlement not confirmed");
        // Set state before external token calls (checks-effects-interactions).
        batch.status = Status.RELEASED;
        for (uint256 i; i < batchSellers[batchId].length; ++i) {
            address seller = batchSellers[batchId][i];
            uint256 amount = sellerPayout[batchId][seller];
            _safeTransfer(seller, amount);
            emit USDCReleased(batchId, seller, amount);
        }
    }

    /// @notice After the deadline, a batch with no oracle-confirmed ZEC leg may be refunded.
    /// @dev Correct refund safety depends on a live oracle and a deadline beyond the ZEC tx expiry.
    function markRefundable(bytes32 batchId) external {
        Batch storage batch = batches[batchId];
        require(
            batch.status == Status.OPEN || batch.status == Status.FUNDED,
            "batch cannot be refunded"
        );
        require(block.timestamp >= batch.deadline, "refund deadline not reached");
        batch.status = Status.REFUNDABLE;
        emit BatchRefundable(batchId);
    }

    function refund(bytes32 batchId) external {
        Batch storage batch = batches[batchId];
        require(batch.status == Status.REFUNDABLE, "batch is not refundable");
        uint256 amount = buyerPaid[batchId][msg.sender];
        require(amount > 0 && !buyerRefunded[batchId][msg.sender], "no refundable deposit");
        buyerRefunded[batchId][msg.sender] = true;
        batch.refundedBuyerCount += 1;
        _safeTransfer(msg.sender, amount);
        emit BuyerRefunded(batchId, msg.sender, amount);
        if (batch.refundedBuyerCount == batch.paidBuyerCount) {
            batch.status = Status.REFUNDED;
        }
    }

    function getBatchStatus(bytes32 batchId) external view returns (
        uint8 status,
        bytes32 planHash,
        uint256 totalBuyerAmount,
        uint256 totalSellerAmount,
        uint256 buyerCount,
        uint256 paidBuyerCount,
        uint256 deadline,
        address quoteToken,
        bytes32 zcashTxid,
        bytes32 zcashBlockHash
    ) {
        Batch storage batch = batches[batchId];
        return (
            uint8(batch.status),
            batch.planHash,
            batch.totalBuyerAmount,
            batch.totalSellerAmount,
            batch.buyerCount,
            batch.paidBuyerCount,
            uint256(batch.deadline),
            address(usdc),
            batch.zcashTxid,
            batch.zcashBlockHash
        );
    }

    function _safeTransfer(address to, uint256 amount) private {
        (bool success, bytes memory data) = address(usdc).call(
            abi.encodeWithSelector(IERC20Quote.transfer.selector, to, amount)
        );
        require(success && (data.length == 0 || abi.decode(data, (bool))), "USDC transfer failed");
    }

    function _safeTransferFrom(address from, address to, uint256 amount) private {
        (bool success, bytes memory data) = address(usdc).call(
            abi.encodeWithSelector(IERC20Quote.transferFrom.selector, from, to, amount)
        );
        require(success && (data.length == 0 || abi.decode(data, (bool))), "USDC transferFrom failed");
    }
}
