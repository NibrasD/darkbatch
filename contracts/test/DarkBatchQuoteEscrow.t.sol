// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "../src/DarkBatchQuoteEscrow.sol";

interface VmQuoteEscrow {
    function warp(uint256 newTimestamp) external;
    function prank(address sender) external;
    function expectRevert(bytes4 selector) external;
}

contract MockUSDC is IERC20Quote {
    mapping(address => uint256) public override balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function mint(address recipient, uint256 amount) external {
        balanceOf[recipient] += amount;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transfer(address recipient, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "balance");
        balanceOf[msg.sender] -= amount;
        balanceOf[recipient] += amount;
        return true;
    }

    function transferFrom(address sender, address recipient, uint256 amount) external returns (bool) {
        require(allowance[sender][msg.sender] >= amount, "allowance");
        require(balanceOf[sender] >= amount, "balance");
        allowance[sender][msg.sender] -= amount;
        balanceOf[sender] -= amount;
        balanceOf[recipient] += amount;
        return true;
    }
}

contract DarkBatchQuoteEscrowTest {
    VmQuoteEscrow private constant vm =
        VmQuoteEscrow(address(uint160(uint256(keccak256("hevm cheat code")))));

    MockUSDC private token;
    DarkBatchQuoteEscrow private escrow;

    address private constant OPERATOR = address(0xA11CE);
    address private constant ORACLE = address(0x0A11CE);
    address private constant BUYER_A = address(0x101);
    address private constant BUYER_B = address(0x202);
    address private constant SELLER_A = address(0x303);
    address private constant SELLER_B = address(0x404);

    bytes32 private batchId = keccak256("darkbatch-test-batch");
    bytes32 private planHash = keccak256("darkbatch-test-plan");

    function setUp() public {
        token = new MockUSDC();
        escrow = new DarkBatchQuoteEscrow(IERC20Quote(address(token)), OPERATOR, ORACLE);

        token.mint(BUYER_A, 100);
        token.mint(BUYER_B, 200);
        vm.prank(BUYER_A);
        token.approve(address(escrow), 100);
        vm.prank(BUYER_B);
        token.approve(address(escrow), 200);
    }

    function _open(uint256 deadline) internal {
        address[] memory buyerAddresses = new address[](2);
        buyerAddresses[0] = BUYER_A;
        buyerAddresses[1] = BUYER_B;
        uint256[] memory buyerAmounts = new uint256[](2);
        buyerAmounts[0] = 100;
        buyerAmounts[1] = 200;

        address[] memory sellerAddresses = new address[](2);
        sellerAddresses[0] = SELLER_A;
        sellerAddresses[1] = SELLER_B;
        uint256[] memory sellerAmounts = new uint256[](2);
        sellerAmounts[0] = 100;
        sellerAmounts[1] = 200;

        vm.prank(OPERATOR);
        escrow.openBatch(
            batchId,
            planHash,
            buyerAddresses,
            buyerAmounts,
            sellerAddresses,
            sellerAmounts,
            deadline
        );

        bytes32 expectedDataHash =
            keccak256(abi.encode(buyerAddresses, buyerAmounts, sellerAddresses, sellerAmounts));
        (
            uint8 status,
            bytes32 storedPlanHash,
            uint256 buyerTotal,
            uint256 sellerTotal,
            uint256 buyerCount,
            uint256 paidBuyerCount,
            uint256 storedDeadline,
            address storedToken,
            bytes32 zecTxid,
            bytes32 zecBlockHash,
            bytes32 dataHash
        ) = escrow.getBatchStatus(batchId);

        require(status == escrow.STATUS_OPEN(), "status");
        require(storedPlanHash == planHash, "plan hash");
        require(buyerTotal == 300 && sellerTotal == 300, "totals");
        require(buyerCount == 2 && paidBuyerCount == 0, "counts");
        require(storedDeadline == deadline, "deadline");
        require(storedToken == address(token), "token");
        require(zecTxid == bytes32(0) && zecBlockHash == bytes32(0), "ZEC ref");
        require(dataHash == expectedDataHash, "escrow data hash");
    }

    function testFundsExactAmountsAndReleasesOnlyAfterOracleAttestation() public {
        _open(block.timestamp + 1 days);

        vm.prank(BUYER_A);
        escrow.fundBuyer(batchId, 0);
        (, , , , , uint256 paidAfterA, , , , ,) = escrow.getBatchStatus(batchId);
        require(paidAfterA == 1, "first buyer funding");
        require(token.balanceOf(address(escrow)) == 100, "first deposit");

        vm.prank(BUYER_B);
        escrow.fundBuyer(batchId, 1);
        (
            uint8 statusAfterFunding, , , , , uint256 paidAfterB, , , , ,
        ) = escrow.getBatchStatus(batchId);
        require(statusAfterFunding == escrow.STATUS_FUNDED(), "fully funded status");
        require(paidAfterB == 2, "all buyers funded");
        require(token.balanceOf(address(escrow)) == 300, "exact locked amount");

        vm.expectRevert(DarkBatchQuoteEscrow.InvalidStatus.selector);
        escrow.releaseBatch(batchId);

        bytes32 zecTxid = keccak256("confirmed-zec-tx");
        bytes32 zecBlockHash = keccak256("confirmed-zec-block");
        vm.prank(ORACLE);
        escrow.markZecConfirmed(batchId, zecTxid, zecBlockHash);
        escrow.releaseBatch(batchId);

        require(token.balanceOf(SELLER_A) == 100, "seller A payout");
        require(token.balanceOf(SELLER_B) == 200, "seller B payout");
        require(token.balanceOf(address(escrow)) == 0, "escrow drained exactly");
        (uint8 finalStatus, , , , , , , , bytes32 finalTxid, bytes32 finalBlockHash, ) =
            escrow.getBatchStatus(batchId);
        require(finalStatus == escrow.STATUS_RELEASED(), "released status");
        require(finalTxid == zecTxid && finalBlockHash == zecBlockHash, "ZEC confirmation reference");
    }

    function testOnlyOracleCanAttestZecConfirmation() public {
        _open(block.timestamp + 1 days);
        vm.prank(BUYER_A);
        escrow.fundBuyer(batchId, 0);
        vm.prank(BUYER_B);
        escrow.fundBuyer(batchId, 1);

        vm.prank(address(0xBAD));
        vm.expectRevert(DarkBatchQuoteEscrow.Unauthorized.selector);
        escrow.markZecConfirmed(batchId, keccak256("tx"), keccak256("block"));
    }

    function testExpiredUnconfirmedBatchRefundsOnlyDepositingBuyers() public {
        _open(block.timestamp + 10);

        vm.prank(BUYER_A);
        escrow.fundBuyer(batchId, 0);
        vm.warp(block.timestamp + 11);

        vm.prank(ORACLE);
        escrow.markRefundable(batchId);
        require(token.balanceOf(address(escrow)) == 100, "only paid amount is locked");

        vm.prank(BUYER_A);
        escrow.refundBuyer(batchId, 0);

        require(token.balanceOf(BUYER_A) == 100, "buyer gets only own deposit back");
        require(token.balanceOf(BUYER_B) == 200, "unpaid buyer balance unchanged");
        require(token.balanceOf(address(escrow)) == 0, "refundable deposit returned");
        (uint8 status, , , , , , , , , ,) = escrow.getBatchStatus(batchId);
        require(status == escrow.STATUS_REFUNDED(), "refunded status");
    }
}
