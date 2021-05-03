//SPDX-License-Identifier: MIT
pragma solidity ^0.6.12;
pragma experimental ABIEncoderV2;

import "@boringcrypto/boring-solidity/contracts/libraries/BoringMath.sol";
import "@boringcrypto/boring-solidity/contracts/Domain.sol";
import "@boringcrypto/boring-solidity/contracts/ERC20.sol";
import "@boringcrypto/boring-solidity/contracts/BoringBatchable.sol";
import "./libraries/SignedSafeMath.sol";
import "./interfaces/IRewarder.sol";

// DAO code/operator management/dutch auction, etc by BoringCrypto
// Staking in DictatorDAO inspired by Chef Nomi's SushiBar (heavily modified) - MIT license (originally WTFPL)
// TimeLock functionality Copyright 2020 Compound Labs, Inc. - BSD 3-Clause "New" or "Revised" License
// Token pool code from SushiSwap MasterChef V2, pioneered by Chef Nomi (I think, under WTFPL) and improved by Keno Budde - MIT license

contract DictatorDAO is IERC20, Domain {
    using BoringMath for uint256;
    using BoringMath128 for uint128;

    string public constant symbol = "DICS";
    string public constant name = "Dictator DAO Shares";
    uint8 public constant decimals = 18;
    uint256 public override totalSupply;

    DictatorToken public immutable token;
    address public operator;

    mapping(address => address) userVote;
    mapping(address => uint256) votes;

    constructor(address initialOperator) public {
        // The DAO is the owner of the DictatorToken
        token = new DictatorToken();
        operator = initialOperator;
    }

    struct User {
        uint128 balance;
        uint128 lockedUntil;
    }

    /// @notice owner > balance mapping.
    mapping(address => User) public users;
    /// @notice owner > spender > allowance mapping.
    mapping(address => mapping(address => uint256)) public override allowance;
    /// @notice owner > nonce mapping. Used in `permit`.
    mapping(address => uint256) public nonces;

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);

    function balanceOf(address user) public view override returns (uint256 balance) {
        return users[user].balance;
    }

    /// @notice Transfers `amount` tokens from `msg.sender` to `to`.
    /// @param to The address to move the tokens.
    /// @param amount of the tokens to move.
    /// @return (bool) Returns True if succeeded.
    function transfer(address to, uint256 amount) public returns (bool) {
        User memory user = users[msg.sender];
        require(block.timestamp >= user.lockedUntil, "Locked");
        // If `amount` is 0, or `msg.sender` is `to` nothing happens
        if (amount != 0) {
            uint256 srcBalance = user.balance;
            require(srcBalance >= amount, "ERC20: balance too low");
            if (msg.sender != to) {
                require(to != address(0), "ERC20: no zero address"); // Moved down so low balance calls safe some gas

                users[msg.sender].balance = (srcBalance - amount).to128(); // Underflow is checked
                users[to].balance += amount.to128(); // Can't overflow because totalSupply would be greater than 2^256-1
            }
        }
        emit Transfer(msg.sender, to, amount);
        return true;
    }

    /// @notice Transfers `amount` tokens from `from` to `to`. Caller needs approval for `from`.
    /// @param from Address to draw tokens from.
    /// @param to The address to move the tokens.
    /// @param amount The token amount to move.
    /// @return (bool) Returns True if succeeded.
    function transferFrom(
        address from,
        address to,
        uint256 amount
    ) public returns (bool) {
        User memory user = users[from];
        require(block.timestamp >= user.lockedUntil, "Locked");
        // If `amount` is 0, or `from` is `to` nothing happens
        if (amount != 0) {
            uint256 srcBalance = user.balance;
            require(srcBalance >= amount, "ERC20: balance too low");

            if (from != to) {
                uint256 spenderAllowance = allowance[from][msg.sender];
                // If allowance is infinite, don't decrease it to save on gas (breaks with EIP-20).
                if (spenderAllowance != type(uint256).max) {
                    require(spenderAllowance >= amount, "ERC20: allowance too low");
                    allowance[from][msg.sender] = spenderAllowance - amount; // Underflow is checked
                }
                require(to != address(0), "ERC20: no zero address"); // Moved down so other failed calls safe some gas

                users[from].balance = (srcBalance - amount).to128(); // Underflow is checked
                users[to].balance += amount.to128(); // Can't overflow because totalSupply would be greater than 2^256-1
            }
        }
        emit Transfer(from, to, amount);
        return true;
    }

    /// @notice Approves `amount` from sender to be spend by `spender`.
    /// @param spender Address of the party that can draw from msg.sender's account.
    /// @param amount The maximum collective amount that `spender` can draw.
    /// @return (bool) Returns True if approved.
    function approve(address spender, uint256 amount) public override returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    // solhint-disable-next-line func-name-mixedcase
    function DOMAIN_SEPARATOR() external view returns (bytes32) {
        return _domainSeparator();
    }

    // keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)");
    bytes32 private constant PERMIT_SIGNATURE_HASH = 0x6e71edae12b1b97f4d1f60370fef10105fa2faae0126114a169c64845d6126c9;

    /// @notice Approves `value` from `owner_` to be spend by `spender`.
    /// @param owner_ Address of the owner.
    /// @param spender The address of the spender that gets approved to draw from `owner_`.
    /// @param value The maximum collective amount that `spender` can draw.
    /// @param deadline This permit must be redeemed before this deadline (UTC timestamp in seconds).
    function permit(
        address owner_,
        address spender,
        uint256 value,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external override {
        require(owner_ != address(0), "ERC20: Owner cannot be 0");
        require(block.timestamp < deadline, "ERC20: Expired");
        require(
            ecrecover(_getDigest(keccak256(abi.encode(PERMIT_SIGNATURE_HASH, owner_, spender, value, nonces[owner_]++, deadline))), v, r, s) ==
                owner_,
            "ERC20: Invalid Signature"
        );
        allowance[owner_][spender] = value;
        emit Approval(owner_, spender, value);
    }

    // Operator Setting
    address pendingOperator;
    uint256 pendingOperatorTime;

    function setOperator(address newOperator) public {
        if (newOperator != pendingOperator) {
            require(votes[newOperator] / 2 > totalSupply, "Not enough votes");
            pendingOperator = newOperator;
            pendingOperatorTime = block.timestamp + 7 days;
        } else {
            if (votes[newOperator] / 2 > totalSupply) {
                require(block.timestamp >= pendingOperatorTime, "Wait longer");
                operator = pendingOperator;
            }
            pendingOperator = address(0);
            pendingOperatorTime = 0;
        }
    }

    function _burn(
        address from,
        address to,
        uint256 shares
    ) internal {
        require(to != address(0), "DictatorShares: no zero address");
        User memory user = users[from];
        require(block.timestamp >= user.lockedUntil, "Locked");
        uint256 amount = (shares * token.balanceOf(address(this))) / totalSupply;
        users[from].balance = user.balance.sub(shares.to128()); // Must check underflow
        totalSupply -= shares;

        votes[userVote[from]] -= shares;

        token.transfer(to, amount);

        emit Transfer(from, address(0), shares);
    }

    /// math is ok, because amount, totalSupply and shares is always 0 <= amount <= 100.000.000 * 10^18
    /// theoretically you can grow the amount/share ratio, but it's not practical and useless
    function mint(
        address to,
        uint256 amount,
        address operatorVote
    ) public returns (bool) {
        require(to != address(0), "DictatorDAO: no zero address");
        User memory user = users[to];

        address previousOperatorVote = userVote[msg.sender];
        uint256 previousBalance = user.balance;
        if (msg.sender != to && previousBalance > 0) {
            // If you mint for someone else and they already have a balance, their last vote gets used
            operatorVote = previousOperatorVote;
        }
        uint256 totalTokens = token.balanceOf(address(this));
        uint256 shares = totalSupply == 0 ? amount : (amount * totalSupply) / totalTokens;
        user.balance = (previousBalance + shares).to128();
        user.lockedUntil = (block.timestamp + 24 hours).to128();
        users[to] = user;
        totalSupply += shares;
        if (previousOperatorVote == operatorVote) {
            votes[operatorVote] += shares;
        } else {
            votes[previousOperatorVote] -= previousBalance;
            votes[operatorVote] = previousBalance + shares;
        }

        token.transferFrom(msg.sender, address(this), amount);

        emit Transfer(address(0), to, shares);
        return true;
    }

    function burn(address to, uint256 shares) public returns (bool) {
        _burn(msg.sender, to, shares);
        return true;
    }

    function burnFrom(
        address from,
        address to,
        uint256 shares
    ) public returns (bool) {
        uint256 spenderAllowance = allowance[from][msg.sender];
        // If allowance is infinite, don't decrease it to save on gas.
        if (spenderAllowance != type(uint256).max) {
            require(spenderAllowance >= shares, "DictatorShares: allowance too low");
            allowance[from][msg.sender] = spenderAllowance - shares; // Underflow is checked
        }
        _burn(from, to, shares);
        return true;
    }

    event QueueTransaction(bytes32 indexed txHash, address indexed target, uint256 value, bytes data, uint256 eta);
    event CancelTransaction(bytes32 indexed txHash, address indexed target, uint256 value, bytes data);
    event ExecuteTransaction(bytes32 indexed txHash, address indexed target, uint256 value, bytes data);

    uint256 public constant GRACE_PERIOD = 14 days;
    uint256 public constant DELAY = 2 days;
    mapping(bytes32 => uint256) public queuedTransactions;

    function queueTransaction(
        address target,
        uint256 value,
        bytes memory data
    ) public returns (bytes32) {
        require(msg.sender == operator, "Operator only");
        require(votes[operator] / 2 > totalSupply, "Not enough votes");

        bytes32 txHash = keccak256(abi.encode(target, value, data));
        uint256 eta = block.timestamp + DELAY;
        queuedTransactions[txHash] = eta;

        emit QueueTransaction(txHash, target, value, data, eta);
        return txHash;
    }

    function cancelTransaction(
        address target,
        uint256 value,
        bytes memory data
    ) public {
        require(msg.sender == operator, "Operator only");

        bytes32 txHash = keccak256(abi.encode(target, value, data));
        queuedTransactions[txHash] = 0;

        emit CancelTransaction(txHash, target, value, data);
    }

    function executeTransaction(
        address target,
        uint256 value,
        bytes memory data
    ) public payable returns (bytes memory) {
        require(msg.sender == operator, "Operator only");
        require(votes[operator] / 2 > totalSupply, "Not enough votes");

        bytes32 txHash = keccak256(abi.encode(target, value, data));
        uint256 eta = queuedTransactions[txHash];
        require(block.timestamp >= eta, "Too early");
        require(block.timestamp <= eta + GRACE_PERIOD, "Tx stale");

        queuedTransactions[txHash] = 0;

        // solium-disable-next-line security/no-call-value
        (bool success, bytes memory returnData) = target.call{value: value}(data);
        require(success, "Tx reverted :(");

        emit ExecuteTransaction(txHash, target, value, data);

        return returnData;
    }
}

interface IMigratorChef {
    // Take the current LP token address and return the new LP token address.
    // Migrator should have full access to the caller's LP token.
    function migrate(IERC20 token) external returns (IERC20);
}

contract DictatorToken is ERC20, BoringBatchable {
    using BoringMath for uint256;
    using BoringMath128 for uint128;
    using SignedSafeMath for int256;
    using BoringERC20 for IERC20;

    string public constant symbol = "DIC";
    string public constant name = "Dictator DAO Token";
    uint8 public constant decimals = 18;
    uint256 public constant override totalSupply = 100000000 * 1e18;

    DictatorDAO public immutable DAO;

    uint256 immutable startTime;
    uint16 public currentWeek;
    mapping(uint16 => uint256) weekShares;
    mapping(address => mapping(uint16 => uint256)) userWeekShares;

    constructor() public {
        DAO = DictatorDAO(msg.sender);

        // Register founding time
        startTime = block.timestamp;

        // Mint all tokens and assign to the contract (no need for minting code after this + save some gas)
        balanceOf[address(this)] = totalSupply;
        emit Transfer(address(0), address(this), totalSupply);
    }

    modifier onlyOperator() {
        require(msg.sender == DAO.operator(), "Dictator: not operator");
        _;
    }

    function price() public view returns (uint256) {
        uint256 timeLeft = (currentWeek + 1) * 7 days + startTime - block.timestamp;
        uint256 timeLeftExp = timeLeft**8; // Max is 1.8e46
        return timeLeftExp / 1e28;
    }

    function buy(uint16 week, address to) public payable returns (uint256) {
        require(week == currentWeek, "Wrong week");
        uint256 weekStart = startTime + currentWeek * 7 days;
        require(block.timestamp >= weekStart, "Not started");
        uint256 elapsed = block.timestamp - weekStart;
        uint256 tokensPerWeek = _tokensPerWeek();
        uint256 currentPrice = price();
        // Shares = value + part of value based on how much of the week has passed (starts at 50%, to 0% at the end of the week)
        uint256 shares = msg.value + elapsed < 7 days ? ((7 days - elapsed) * msg.value) / 14 days : 0;
        userWeekShares[to][week] += shares;
        weekShares[week] += shares;
        require(weekShares[week].mul(1e18) / currentPrice < tokensPerWeek, "Oversold");
    }

    function nextWeek() public {
        require(weekShares[currentWeek].mul(1e18) / price() > _tokensPerWeek(), "Not fully sold");
        currentWeek++;
    }

    function _tokensPerWeek() internal view returns (uint256) {
        uint256 elapsed = (block.timestamp - startTime) / 7 days;
        return
            elapsed < 2 ? 1000000 : elapsed < 50 ? 100000e18 : elapsed < 100 ? 50000e18 : elapsed < 150 ? 30000e18 : elapsed < 200
                ? 20000e18
                : 0;
    }

    function _tokensPerBlock() internal view returns (uint256) {
        uint256 elapsed = (block.timestamp - startTime) / 7 days;
        return elapsed < 2 ? 0 : elapsed < 50 ? 219780e14 : elapsed < 100 ? 109890e14 : elapsed < 150 ? 65934e14 : elapsed < 200 ? 43956e14 : 0;
    }

    function retrieveOperatorPayment(address to) public onlyOperator returns (bool success) {
        (success, ) = to.call{value: address(this).balance}("");
    }

    event Deposit(address indexed user, uint256 indexed pid, uint256 amount, address indexed to);
    event Withdraw(address indexed user, uint256 indexed pid, uint256 amount, address indexed to);
    event EmergencyWithdraw(address indexed user, uint256 indexed pid, uint256 amount, address indexed to);
    event Harvest(address indexed user, uint256 indexed pid, uint256 amount);
    event LogPoolAddition(uint256 indexed pid, uint256 allocPoint, IERC20 indexed poolToken, IRewarder indexed rewarder);
    event LogSetPool(uint256 indexed pid, uint256 allocPoint, IRewarder indexed rewarder, bool overwrite);
    event LogUpdatePool(uint256 indexed pid, uint64 lastRewardBlock, uint256 lpSupply, uint256 accTokensPerShare);

    /// @notice Info of each Distributor user.
    /// `amount` LP token amount the user has provided.
    /// `rewardDebt` The amount of tokens entitled to the user.
    struct UserInfo {
        uint256 amount;
        int256 rewardDebt;
    }

    /// @notice Info of each Distributor pool.
    /// `allocPoint` The amount of allocation points assigned to the pool.
    /// Also known as the amount of tokens to distribute per block.
    struct PoolInfo {
        uint128 accTokensPerShare;
        uint64 lastRewardBlock;
        uint64 allocPoint;
    }

    /// @notice Info of each Distributor pool.
    PoolInfo[] public poolInfo;
    /// @notice Address of the LP token for each Distributor pool.
    IERC20[] public poolToken;
    /// @notice Address of each `IRewarder` contract in Distributor.
    IRewarder[] public rewarder;

    /// @notice Info of each user that stakes LP tokens.
    mapping(uint256 => mapping(address => UserInfo)) public userInfo;
    /// @dev Total allocation points. Must be the sum of all allocation points in all pools.
    uint256 public totalAllocPoint;

    // @notice The migrator contract. It has a lot of power. Can only be set through governance (owner).
    IMigratorChef public migrator;

    uint256 private constant ACC_TOKENS_PRECISION = 1e12;

    /// @notice Returns the number of MCV2 pools.
    function poolLength() public view returns (uint256 pools) {
        pools = poolInfo.length;
    }

    /// @notice Add a new LP to the pool. Can only be called by the owner.
    /// DO NOT add the same LP token more than once. Rewards will be messed up if you do.
    /// @param allocPoint AP of the new pool.
    /// @param poolToken_ Address of the LP ERC-20 token.
    /// @param _rewarder Address of the rewarder delegate.
    function addPool(
        uint256 allocPoint,
        IERC20 poolToken_,
        IRewarder _rewarder
    ) public onlyOperator {
        uint256 lastRewardBlock = block.number;
        totalAllocPoint = totalAllocPoint.add(allocPoint);
        poolToken.push(poolToken_);
        rewarder.push(_rewarder);

        poolInfo.push(PoolInfo({allocPoint: allocPoint.to64(), lastRewardBlock: lastRewardBlock.to64(), accTokensPerShare: 0}));
        emit LogPoolAddition(poolToken.length.sub(1), allocPoint, poolToken_, _rewarder);
    }

    /// @notice Update the given pool's tokens allocation point and `IRewarder` contract. Can only be called by the owner.
    /// @param _pid The index of the pool. See `poolInfo`.
    /// @param _allocPoint New AP of the pool.
    /// @param _rewarder Address of the rewarder delegate.
    /// @param overwrite True if _rewarder should be `set`. Otherwise `_rewarder` is ignored.
    function setPool(
        uint256 _pid,
        uint256 _allocPoint,
        IRewarder _rewarder,
        bool overwrite
    ) public onlyOperator {
        totalAllocPoint = totalAllocPoint.sub(poolInfo[_pid].allocPoint).add(_allocPoint);
        poolInfo[_pid].allocPoint = _allocPoint.to64();
        if (overwrite) {
            rewarder[_pid] = _rewarder;
        }
        emit LogSetPool(_pid, _allocPoint, overwrite ? _rewarder : rewarder[_pid], overwrite);
    }

    /// @notice Set the `migrator` contract. Can only be called by the owner.
    /// @param _migrator The contract address to set.
    function setMigrator(IMigratorChef _migrator) public onlyOperator {
        migrator = _migrator;
    }

    /// @notice Migrate LP token to another LP contract through the `migrator` contract.
    /// @param pid The index of the pool. See `poolInfo`.
    function migratePool(uint256 pid) public {
        require(address(migrator) != address(0), "DDAO: no migrator set");
        IERC20 _poolToken = poolToken[pid];
        uint256 bal = _poolToken.balanceOf(address(this));
        _poolToken.approve(address(migrator), bal);
        IERC20 newPoolToken = migrator.migrate(_poolToken);
        require(bal == newPoolToken.balanceOf(address(this)), "DDAO: migrated balance must match");
        poolToken[pid] = newPoolToken;
    }

    /// @notice View function to see pending tokens on frontend.
    /// @param _pid The index of the pool. See `poolInfo`.
    /// @param _user Address of user.
    /// @return pending tokens reward for a given user.
    function pendingTokens(uint256 _pid, address _user) external view returns (uint256 pending) {
        PoolInfo memory pool = poolInfo[_pid];
        UserInfo storage user = userInfo[_pid][_user];
        uint256 accTokensPerShare = pool.accTokensPerShare;
        uint256 lpSupply = poolToken[_pid].balanceOf(address(this));
        if (block.number > pool.lastRewardBlock && lpSupply != 0) {
            uint256 blocks = block.number.sub(pool.lastRewardBlock);
            uint256 tokensReward = blocks.mul(_tokensPerBlock()).mul(pool.allocPoint) / totalAllocPoint;
            accTokensPerShare = accTokensPerShare.add(tokensReward.mul(ACC_TOKENS_PRECISION) / lpSupply);
        }
        pending = int256(user.amount.mul(accTokensPerShare) / ACC_TOKENS_PRECISION).sub(user.rewardDebt).toUInt256();
    }

    /// @notice Update reward variables for all pools. Be careful of gas spending!
    /// @param pids Pool IDs of all to be updated. Make sure to update all active pools.
    function massUpdatePools(uint256[] calldata pids) external {
        uint256 len = pids.length;
        for (uint256 i = 0; i < len; ++i) {
            updatePool(pids[i]);
        }
    }

    /// @notice Update reward variables of the given pool.
    /// @param pid The index of the pool. See `poolInfo`.
    /// @return pool Returns the pool that was updated.
    function updatePool(uint256 pid) public returns (PoolInfo memory pool) {
        pool = poolInfo[pid];
        if (block.number > pool.lastRewardBlock) {
            uint256 lpSupply = poolToken[pid].balanceOf(address(this));
            if (lpSupply > 0) {
                uint256 blocks = block.number.sub(pool.lastRewardBlock);
                uint256 tokensReward = blocks.mul(_tokensPerBlock()).mul(pool.allocPoint) / totalAllocPoint;
                pool.accTokensPerShare = pool.accTokensPerShare.add((tokensReward.mul(ACC_TOKENS_PRECISION) / lpSupply).to128());
            }
            pool.lastRewardBlock = block.number.to64();
            poolInfo[pid] = pool;
            emit LogUpdatePool(pid, pool.lastRewardBlock, lpSupply, pool.accTokensPerShare);
        }
    }

    /// @notice Deposit LP tokens to Dictator DAO for token allocation.
    /// @param pid The index of the pool. See `poolInfo`.
    /// @param amount LP token amount to deposit.
    /// @param to The receiver of `amount` deposit benefit.
    function deposit(
        uint256 pid,
        uint256 amount,
        address to
    ) public {
        PoolInfo memory pool = updatePool(pid);
        UserInfo storage user = userInfo[pid][to];

        // Effects
        user.amount = user.amount.add(amount);
        user.rewardDebt = user.rewardDebt.add(int256(amount.mul(pool.accTokensPerShare) / ACC_TOKENS_PRECISION));

        // Interactions
        IRewarder _rewarder = rewarder[pid];
        if (address(_rewarder) != address(0)) {
            _rewarder.onTokensReward(pid, to, to, 0, user.amount);
        }

        poolToken[pid].safeTransferFrom(msg.sender, address(this), amount);

        emit Deposit(msg.sender, pid, amount, to);
    }

    /// @notice Withdraw LP tokens from MCV2.
    /// @param pid The index of the pool. See `poolInfo`.
    /// @param amount LP token amount to withdraw.
    /// @param to Receiver of the LP tokens.
    function withdraw(
        uint256 pid,
        uint256 amount,
        address to
    ) public {
        PoolInfo memory pool = updatePool(pid);
        UserInfo storage user = userInfo[pid][msg.sender];

        // Effects
        user.rewardDebt = user.rewardDebt.sub(int256(amount.mul(pool.accTokensPerShare) / ACC_TOKENS_PRECISION));
        user.amount = user.amount.sub(amount);

        // Interactions
        IRewarder _rewarder = rewarder[pid];
        if (address(_rewarder) != address(0)) {
            _rewarder.onTokensReward(pid, msg.sender, to, 0, user.amount);
        }

        poolToken[pid].safeTransfer(to, amount);

        emit Withdraw(msg.sender, pid, amount, to);
    }

    /// @notice Harvest proceeds for transaction sender to `to`.
    /// @param pid The index of the pool. See `poolInfo`.
    /// @param to Receiver of tokens rewards.
    function harvest(uint256 pid, address to) public {
        PoolInfo memory pool = updatePool(pid);
        UserInfo storage user = userInfo[pid][msg.sender];
        int256 accumulatedTokens = int256(user.amount.mul(pool.accTokensPerShare) / ACC_TOKENS_PRECISION);
        uint256 _pendingTokens = accumulatedTokens.sub(user.rewardDebt).toUInt256();

        // Effects
        user.rewardDebt = accumulatedTokens;

        // Interactions
        if (_pendingTokens != 0) {
            balanceOf[address(this)] = balanceOf[address(this)].sub(_pendingTokens);
            balanceOf[to] += balanceOf[to];
            emit Transfer(address(this), to, _pendingTokens);
        }

        IRewarder _rewarder = rewarder[pid];
        if (address(_rewarder) != address(0)) {
            _rewarder.onTokensReward(pid, msg.sender, to, _pendingTokens, user.amount);
        }

        emit Harvest(msg.sender, pid, _pendingTokens);
    }

    /// @notice Withdraw LP tokens from MCV2 and harvest proceeds for transaction sender to `to`.
    /// @param pid The index of the pool. See `poolInfo`.
    /// @param amount LP token amount to withdraw.
    /// @param to Receiver of the LP tokens and tokens rewards.
    function withdrawAndHarvest(
        uint256 pid,
        uint256 amount,
        address to
    ) public {
        PoolInfo memory pool = updatePool(pid);
        UserInfo storage user = userInfo[pid][msg.sender];
        int256 accumulatedTokens = int256(user.amount.mul(pool.accTokensPerShare) / ACC_TOKENS_PRECISION);
        uint256 _pendingTokens = accumulatedTokens.sub(user.rewardDebt).toUInt256();

        // Effects
        user.rewardDebt = accumulatedTokens.sub(int256(amount.mul(pool.accTokensPerShare) / ACC_TOKENS_PRECISION));
        user.amount = user.amount.sub(amount);

        // Interactions
        balanceOf[address(this)] = balanceOf[address(this)].sub(_pendingTokens);
        balanceOf[to] += balanceOf[to];
        emit Transfer(address(this), to, _pendingTokens);

        IRewarder _rewarder = rewarder[pid];
        if (address(_rewarder) != address(0)) {
            _rewarder.onTokensReward(pid, msg.sender, to, _pendingTokens, user.amount);
        }

        poolToken[pid].safeTransfer(to, amount);

        emit Withdraw(msg.sender, pid, amount, to);
        emit Harvest(msg.sender, pid, _pendingTokens);
    }

    /// @notice Withdraw without caring about rewards. EMERGENCY ONLY.
    /// @param pid The index of the pool. See `poolInfo`.
    /// @param to Receiver of the LP tokens.
    function emergencyWithdraw(uint256 pid, address to) public {
        UserInfo storage user = userInfo[pid][msg.sender];
        uint256 amount = user.amount;
        user.amount = 0;
        user.rewardDebt = 0;

        IRewarder _rewarder = rewarder[pid];
        if (address(_rewarder) != address(0)) {
            _rewarder.onTokensReward(pid, msg.sender, to, 0, 0);
        }

        // Note: transfer can fail or succeed if `amount` is zero.
        poolToken[pid].safeTransfer(to, amount);
        emit EmergencyWithdraw(msg.sender, pid, amount, to);
    }
}
