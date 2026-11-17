// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title StandardVault
 * @notice One vault per pool. Interface and rules: docs/standard-vault/interface-spec.md.
 *         Funds leave only to whitelisted payees, the fixed profit address or the fixed
 *         evacuation address. Not upgradeable: no proxy, no delegatecall, no selfdestruct.
 * @dev There is deliberately no reentrancy lock (TVM charges every SSTORE in full, so a lock
 *      would add two to every payout). Every state-changing entry point requires the operator or
 *      a manager, and none of those can be a payee, a platform address or a listed token, so a
 *      callee cannot re-enter with authority. Bookkeeping is still written before external calls.
 */
contract StandardVault {
    address public constant TRX = address(0);
    uint256 public constant PROPOSAL_TTL = 7 days;
    uint256 public constant DAY_OFFSET = 8 hours;
    uint256 public constant MAX_BATCH = 20;
    string public constant VERSION = "StandardVault/1";

    uint8 private constant ADD_PAYEE = 1;
    uint8 private constant REMOVE_PAYEE = 2;
    uint8 private constant SET_DAILY_LIMIT = 3;
    uint8 private constant SET_OPERATOR = 4;
    uint8 private constant REPLACE_MANAGER = 5;
    uint8 private constant ADD_TOKEN = 6;
    uint8 private constant UNLOCK = 7;

    uint8 private constant PENDING = 1;
    uint8 private constant EXECUTED = 2;
    uint8 private constant CANCELLED = 3;
    uint8 private constant EXPIRED = 4;
    uint8 private constant VOIDED = 5;

    struct Proposal {
        address target;
        uint8 action;
        uint8 state; // only PENDING, EXECUTED or CANCELLED is stored; EXPIRED and VOIDED are derived
        uint64 createdAt;
        address proposer;
        uint64 epoch;
        uint256 value;
    }

    bytes32 public immutable poolName;
    address public immutable profitAddress;
    address public immutable evacuationAddress;

    address public operator;
    bool public locked;
    address[2] private _managers;
    uint256 public managerEpoch;
    uint256 public proposalCount;

    address[] private _tokens;
    mapping(address => bool) private _isToken;
    mapping(address => uint256) private _dailyLimit;
    // (spent << 64) | day, so a payout costs one SSTORE. spent never exceeds type(uint192).max
    // because limits above that are treated as type(uint192).max.
    mapping(address => uint256) private _spentWord;

    address[] private _payees;
    mapping(address => uint256) private _payeeIndex; // position in _payees plus one; 0 = not a payee

    mapping(uint256 => Proposal) private _proposals;
    mapping(uint256 => uint256) private _epochStartedAt;

    event Paid(address indexed asset, address indexed to, uint256 amount, bytes32 indexed ref);
    event Locked(address indexed by);
    event Unlocked(uint256 indexed proposalId);
    event Evacuated(address indexed asset, address indexed to, uint256 amount);
    event EvacuationSkipped(address indexed asset, uint256 amount);
    event Swept(address indexed token, address indexed to, uint256 amount);
    event Proposed(uint256 indexed id, uint8 indexed action, address target, uint256 value,
                   address indexed proposer, uint256 expiresAt);
    event Confirmed(uint256 indexed id, address indexed by);
    event Cancelled(uint256 indexed id, address indexed by);
    event PayeeAdded(address indexed payee);
    event PayeeRemoved(address indexed payee);
    event DailyLimitChanged(address indexed asset, uint256 oldLimit, uint256 newLimit);
    event OperatorChanged(address indexed oldOperator, address indexed newOperator);
    event ManagerReplaced(uint256 indexed slot, address indexed oldManager, address indexed newManager);
    event TokenAdded(address indexed token, uint256 dailyLimit);

    constructor(
        bytes32 poolName_,
        address profitAddress_,
        address evacuationAddress_,
        address operator_,
        address[2] memory managers_,
        address[] memory tokens_,
        uint256[] memory tokenDailyLimits_,
        uint256 trxDailyLimit_,
        address[] memory initialPayees_
    ) {
        address[5] memory roles = [profitAddress_, evacuationAddress_, operator_, managers_[0], managers_[1]];
        for (uint256 i; i < 5; ++i) {
            require(roles[i] != address(0) && roles[i] != address(this), "SV: bad config");
            for (uint256 j = i + 1; j < 5; ++j) require(roles[i] != roles[j], "SV: bad config");
        }
        require(tokens_.length == tokenDailyLimits_.length, "SV: bad config");

        poolName = poolName_;
        profitAddress = profitAddress_;
        evacuationAddress = evacuationAddress_;
        operator = operator_;
        _managers = managers_;

        for (uint256 i; i < tokens_.length; ++i) {
            require(tokens_[i].code.length != 0 && _isFree(tokens_[i]), "SV: bad config");
            _addToken(tokens_[i], tokenDailyLimits_[i]);
        }
        _dailyLimit[TRX] = trxDailyLimit_;
        emit DailyLimitChanged(TRX, 0, trxDailyLimit_);
        for (uint256 i; i < initialPayees_.length; ++i) {
            require(_isFree(initialPayees_[i]), "SV: bad config");
            _addPayee(initialPayees_[i]);
        }
    }

    // On TRON a plain TRX transfer (TransferContract) credits the vault without running this;
    // it only runs when another contract sends TRX along with a call.
    receive() external payable {}

    // ------------------------------------------------------------------ funds

    function payout(address asset, address to, uint256 amount, bytes32 ref) external {
        require(msg.sender == operator, "SV: not operator");
        if (_checkPayout(asset == TRX || _isToken[asset], locked, to, amount)) {
            (uint256 day, uint256 spent) = _spentNow(asset);
            _setSpent(asset, day, _accrue(spent, _limit(asset), amount));
        }
        if (asset == TRX) _sendTrx(to, amount);
        else _sendToken(asset, to, amount, _tokenBalance(asset));
        emit Paid(asset, to, amount, ref);
    }

    /// @dev Every item is validated and the day's total recorded before the first transfer.
    function payoutBatch(
        address asset,
        address[] calldata to,
        uint256[] calldata amounts,
        bytes32[] calldata refs
    ) external {
        require(msg.sender == operator, "SV: not operator");
        uint256 n = to.length;
        require(n != 0 && n <= MAX_BATCH && amounts.length == n && refs.length == n, "SV: bad batch");

        bool isTrx = asset == TRX;
        bool allowed = isTrx || _isToken[asset];
        bool isLocked = locked;
        (uint256 day, uint256 spent) = _spentNow(asset);
        uint256 limit = _limit(asset);
        bool limited;
        for (uint256 i; i < n; ++i) {
            if (_checkPayout(allowed, isLocked, to[i], amounts[i])) {
                spent = _accrue(spent, limit, amounts[i]);
                limited = true;
            }
        }
        if (limited) _setSpent(asset, day, spent);

        uint256 balance = isTrx ? 0 : _tokenBalance(asset);
        for (uint256 i; i < n; ++i) {
            if (isTrx) _sendTrx(to[i], amounts[i]);
            else balance = _sendToken(asset, to[i], amounts[i], balance);
            emit Paid(asset, to[i], amounts[i], refs[i]);
        }
    }

    function lock() external {
        _onlyOperatorOrManager();
        _lock();
    }

    function evacuateAll() external {
        _onlyOperatorOrManager();
        _lock();
        address to = evacuationAddress;
        uint256 n = _tokens.length;
        for (uint256 i; i < n; ++i) {
            address token = _tokens[i];
            (bool ok, uint256 amount) = _balanceOf(token);
            if (ok) {
                if (amount == 0) continue;
                ok = _rawTransfer(token, to, amount) && _hasBalance(token, 0);
            }
            if (ok) emit Evacuated(token, to, amount);
            else emit EvacuationSkipped(token, amount);
        }
        uint256 trx = address(this).balance;
        if (trx != 0) {
            if (_rawSendTrx(to, trx)) emit Evacuated(TRX, to, trx);
            else emit EvacuationSkipped(TRX, trx);
        }
    }

    function sweep(address token, address to) external {
        _onlyOperatorOrManager();
        require(token != TRX && !_isToken[token], "SV: listed token");
        require(to == profitAddress || to == evacuationAddress, "SV: bad destination");
        require(!locked || to == evacuationAddress, "SV: locked");
        (bool ok, uint256 amount) = _balanceOf(token);
        require(ok && amount != 0, "SV: nothing to sweep");
        require(_rawTransfer(token, to, amount), "SV: transfer failed");
        require(_hasBalance(token, 0), "SV: debit mismatch");
        emit Swept(token, to, amount);
    }

    // ------------------------------------------------------------ proposals

    function propose(uint8 action, address target, uint256 value) external returns (uint256 id) {
        _onlyManager();
        _validate(action, target, value);
        // Read before the field writes: a storage read between them stops the optimizer from
        // merging each packed slot into a single SSTORE.
        uint64 epoch = uint64(managerEpoch);
        id = ++proposalCount;
        Proposal storage p = _proposals[id];
        p.target = target;
        p.action = action;
        p.state = PENDING;
        p.createdAt = uint64(block.timestamp);
        p.proposer = msg.sender;
        p.epoch = epoch;
        if (value != 0) p.value = value;
        emit Proposed(id, action, target, value, msg.sender, block.timestamp + PROPOSAL_TTL);
    }

    function confirm(uint256 id) external {
        _onlyManager();
        Proposal storage p = _pending(id);
        require(msg.sender != p.proposer, "SV: own proposal");
        uint8 action = p.action;
        address target = p.target;
        uint256 value = p.value;
        _validate(action, target, value);
        p.state = EXECUTED;
        emit Confirmed(id, msg.sender);
        _execute(id, action, target, value);
    }

    function cancel(uint256 id) external {
        _onlyManager();
        _pending(id).state = CANCELLED;
        emit Cancelled(id, msg.sender);
    }

    // ---------------------------------------------------------------- views

    function managers(uint256 slot) external view returns (address) {
        return _managers[slot];
    }

    function isPayee(address account) external view returns (bool) {
        return _payeeIndex[account] != 0;
    }

    function payees() external view returns (address[] memory) {
        return _payees;
    }

    function isToken(address token) external view returns (bool) {
        return _isToken[token];
    }

    function tokens() external view returns (address[] memory) {
        return _tokens;
    }

    function dailyLimit(address asset) external view returns (uint256) {
        return _dailyLimit[asset];
    }

    function today() public view returns (uint256) {
        return (block.timestamp + DAY_OFFSET) / 1 days;
    }

    function spentToday(address asset) external view returns (uint256) {
        (, uint256 spent) = _spentNow(asset);
        return spent;
    }

    function remainingToday(address asset) external view returns (uint256) {
        (, uint256 spent) = _spentNow(asset);
        uint256 limit = _limit(asset);
        return spent < limit ? limit - spent : 0;
    }

    function balances() external view returns (address[] memory assets, uint256[] memory amounts) {
        uint256 n = _tokens.length;
        assets = new address[](n + 1);
        amounts = new uint256[](n + 1);
        amounts[0] = address(this).balance;
        for (uint256 i; i < n; ++i) {
            address token = _tokens[i];
            assets[i + 1] = token;
            (, amounts[i + 1]) = _balanceOf(token);
        }
    }

    function getProposal(uint256 id) external view returns (
        uint8 action, address target, uint256 value, address proposer,
        uint256 createdAt, uint256 expiresAt, uint256 epoch, uint8 state)
    {
        state = proposalState(id);
        if (state != 0) {
            Proposal storage p = _proposals[id];
            (action, target, value, proposer) = (p.action, p.target, p.value, p.proposer);
            (createdAt, epoch) = (p.createdAt, p.epoch);
            expiresAt = createdAt + PROPOSAL_TTL;
        }
    }

    /// @dev An unconfirmed proposal ends either by expiry or by a manager change, whichever came
    ///      first; the state reports that cause and does not change afterwards.
    function proposalState(uint256 id) public view returns (uint8) {
        Proposal storage p = _proposals[id];
        uint8 state = p.state;
        if (state != PENDING) return state;
        uint256 expiresAt = uint256(p.createdAt) + PROPOSAL_TTL;
        uint256 epoch = p.epoch;
        if (epoch != managerEpoch) return expiresAt <= _epochStartedAt[epoch + 1] ? EXPIRED : VOIDED;
        return block.timestamp >= expiresAt ? EXPIRED : PENDING;
    }

    // ------------------------------------------------------------- internal

    function _isManager(address account) private view returns (bool) {
        return account == _managers[0] || account == _managers[1];
    }

    function _onlyManager() private view {
        require(_isManager(msg.sender), "SV: not manager");
    }

    function _onlyOperatorOrManager() private view {
        require(msg.sender == operator || _isManager(msg.sender), "SV: not operator or manager");
    }

    /// @dev True when `account` holds no role, is no platform address, listed token or payee.
    function _isFree(address account) private view returns (bool) {
        return account != address(0) && account != address(this) && account != operator
            && !_isManager(account) && account != profitAddress && account != evacuationAddress
            && !_isToken[account] && _payeeIndex[account] == 0;
    }

    function _lock() private {
        if (!locked) {
            locked = true;
            emit Locked(msg.sender);
        }
    }

    /// @return limited whether the payout counts against the daily limit
    function _checkPayout(bool assetAllowed, bool isLocked, address to, uint256 amount)
        private view returns (bool limited)
    {
        require(amount != 0, "SV: zero amount");
        require(assetAllowed, "SV: asset not allowed");
        if (isLocked) {
            require(to == evacuationAddress, "SV: locked");
            return false;
        }
        if (to == profitAddress || to == evacuationAddress) return false;
        require(_payeeIndex[to] != 0, "SV: payee not allowed");
        return true;
    }

    function _spentNow(address asset) private view returns (uint256 day, uint256 spent) {
        day = today();
        uint256 word = _spentWord[asset];
        if (uint64(word) == day) spent = word >> 64;
    }

    function _setSpent(address asset, uint256 day, uint256 spent) private {
        _spentWord[asset] = (spent << 64) | day;
    }

    function _limit(address asset) private view returns (uint256 limit) {
        limit = _dailyLimit[asset];
        if (limit > type(uint192).max) limit = type(uint192).max;
    }

    function _accrue(uint256 spent, uint256 limit, uint256 amount) private pure returns (uint256) {
        require(spent <= limit && amount <= limit - spent, "SV: daily limit");
        return spent + amount;
    }

    function _sendTrx(address to, uint256 amount) private {
        require(address(this).balance >= amount, "SV: insufficient balance");
        require(_rawSendTrx(to, amount), "SV: transfer failed");
    }

    function _tokenBalance(address token) private view returns (uint256 amount) {
        bool ok;
        (ok, amount) = _balanceOf(token);
        require(ok, "SV: transfer failed");
    }

    /// @return left the vault balance after the transfer, verified against the token
    function _sendToken(address token, address to, uint256 amount, uint256 before)
        private returns (uint256 left)
    {
        require(before >= amount, "SV: insufficient balance");
        require(_rawTransfer(token, to, amount), "SV: transfer failed");
        left = before - amount;
        require(_hasBalance(token, left), "SV: debit mismatch");
    }

    function _hasBalance(address token, uint256 expected) private view returns (bool) {
        (bool ok, uint256 amount) = _balanceOf(token);
        return ok && amount == expected;
    }

    // Never reverts: evacuateAll must be able to skip a token whose balanceOf fails.
    function _balanceOf(address token) private view returns (bool ok, uint256 amount) {
        assembly ("memory-safe") {
            mstore(0x00, shl(224, 0x70a08231))
            mstore(0x04, address())
            let success := staticcall(gas(), token, 0x00, 0x24, 0x00, 0x20)
            ok := and(success, gt(returndatasize(), 0x1f))
            amount := mul(mload(0x00), ok)
        }
    }

    // The return data is ignored on purpose: TRON mainnet USDT returns false on a successful
    // transfer. Callers judge success by the vault balance dropping by exactly the amount.
    function _rawTransfer(address token, address to, uint256 amount) private returns (bool ok) {
        assembly ("memory-safe") {
            let p := mload(0x40)
            mstore(p, shl(224, 0xa9059cbb))
            mstore(add(p, 0x04), and(to, 0xffffffffffffffffffffffffffffffffffffffff))
            mstore(add(p, 0x24), amount)
            ok := call(gas(), token, 0, p, 0x44, 0, 0)
        }
    }

    function _rawSendTrx(address to, uint256 amount) private returns (bool ok) {
        assembly ("memory-safe") {
            ok := call(gas(), to, amount, 0, 0, 0, 0)
        }
    }

    function _validate(uint8 action, address target, uint256 value) private view {
        if (action == ADD_PAYEE || action == SET_OPERATOR) {
            require(value == 0 && _isFree(target), "SV: bad target");
        } else if (action == REMOVE_PAYEE) {
            require(value == 0 && _payeeIndex[target] != 0, "SV: bad target");
        } else if (action == SET_DAILY_LIMIT) {
            require(target == TRX || _isToken[target], "SV: bad target");
        } else if (action == REPLACE_MANAGER) {
            require(value < 2 && _isFree(target), "SV: bad target");
        } else if (action == ADD_TOKEN) {
            require(target.code.length != 0 && _isFree(target), "SV: bad target");
        } else if (action == UNLOCK) {
            require(target == address(0) && value == 0, "SV: bad target");
            require(locked, "SV: not locked");
        } else {
            revert("SV: bad action");
        }
    }

    function _pending(uint256 id) private view returns (Proposal storage p) {
        p = _proposals[id];
        uint8 state = p.state;
        require(state != 0, "SV: no proposal");
        require(state == PENDING, "SV: not pending");
        require(p.epoch == managerEpoch && block.timestamp < uint256(p.createdAt) + PROPOSAL_TTL,
                "SV: expired");
    }

    function _execute(uint256 id, uint8 action, address target, uint256 value) private {
        if (action == ADD_PAYEE) {
            _addPayee(target);
        } else if (action == REMOVE_PAYEE) {
            _removePayee(target);
        } else if (action == SET_DAILY_LIMIT) {
            uint256 old = _dailyLimit[target];
            _dailyLimit[target] = value;
            emit DailyLimitChanged(target, old, value);
        } else if (action == SET_OPERATOR) {
            address old = operator;
            operator = target;
            emit OperatorChanged(old, target);
        } else if (action == REPLACE_MANAGER) {
            address old = _managers[value];
            _managers[value] = target;
            uint256 epoch = managerEpoch + 1;
            managerEpoch = epoch;
            _epochStartedAt[epoch] = block.timestamp;
            emit ManagerReplaced(value, old, target);
        } else if (action == ADD_TOKEN) {
            _addToken(target, value);
        } else {
            locked = false;
            emit Unlocked(id);
        }
    }

    function _addPayee(address payee) private {
        _payees.push(payee);
        _payeeIndex[payee] = _payees.length;
        emit PayeeAdded(payee);
    }

    function _removePayee(address payee) private {
        uint256 index = _payeeIndex[payee];
        uint256 last = _payees.length;
        if (index != last) {
            address moved = _payees[last - 1];
            _payees[index - 1] = moved;
            _payeeIndex[moved] = index;
        }
        _payees.pop();
        delete _payeeIndex[payee];
        emit PayeeRemoved(payee);
    }

    function _addToken(address token, uint256 limit) private {
        _isToken[token] = true;
        _tokens.push(token);
        _dailyLimit[token] = limit;
        emit TokenAdded(token, limit);
    }
}
