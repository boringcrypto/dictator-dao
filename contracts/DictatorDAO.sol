//SPDX-License-Identifier: MIT
pragma solidity ^0.6.12;
pragma experimental ABIEncoderV2;

import "@boringcrypto/boring-solidity/contracts/libraries/BoringMath.sol";
import "@boringcrypto/boring-solidity/contracts/libraries/BoringERC20.sol";
import "@boringcrypto/boring-solidity/contracts/ERC20.sol";
import "@boringcrypto/boring-solidity/contracts/BoringBatchable.sol";
import "@boringcrypto/boring-solidity/contracts/BoringOwnable.sol";
import "./libraries/SignedSafeMath.sol";
import "./interfaces/IRewarder.sol";
import "hardhat/console.sol";

/// Inspired by Chef Nomi's SushiBar
contract DictatorShares is ERC20 {
    using BoringMath for uint256;
    using BoringERC20 for IERC20;

    string public constant symbol = "DICS";
    string public constant name = "Dictator DAO Shares";
    uint8 public constant decimals = 18;
    uint256 public totalSupply;

    IERC20 public token;

    constructor(IERC20 token_) public {
        token = token_;
    }

    /// math is ok, because amount, totalSupply and shares is always 0 <= amount <= 100.000.000 * 10^18
    /// theoretically you can grow the amount/share ratio, but it's not practical and useless
    function mint(uint256 amount, address to) public returns (bool) {
        uint256 totalTokens = token.balanceOf(address(this));
        uint256 shares = totalSupply == 0 ? amount : (amount * totalSupply) / totalTokens;
        balanceOf[to] += shares;
        totalSupply += shares;

        token.safeTransferFrom(msg.sender, address(this), amount);

        emit Transfer(address(0), to, shares);
        return true;
    }

    function burn(address to, uint256 shares) public returns (bool) {
        uint256 amount = (shares * token.balanceOf(address(this))) / totalSupply;
        balanceOf[msg.sender] = balanceOf[msg.sender].sub(shares); // Must check underflow
        totalSupply -= shares;

        token.safeTransfer(to, amount);

        emit Transfer(msg.sender, address(0), shares);
        return true;
    }

    function burnFrom(
        address from,
        address to,
        uint256 shares
    ) public returns (bool) {
        if (shares != 0) {
            uint256 srcBalance = balanceOf[from];
            require(srcBalance >= shares, "DictatorShares: balance too low");

            uint256 spenderAllowance = allowance[from][msg.sender];
            // If allowance is infinite, don't decrease it to save on gas.
            if (spenderAllowance != type(uint256).max) {
                require(spenderAllowance >= shares, "DictatorShares: allowance too low");
                allowance[from][msg.sender] = spenderAllowance - shares; // Underflow is checked
            }
            require(to != address(0), "DictatorShares: no zero address"); // Moved down so other failed calls safe some gas
            balanceOf[from] = srcBalance - shares; // Underflow is checked

            token.safeTransfer(to, (shares * token.balanceOf(address(this))) / totalSupply);
        }

        emit Transfer(from, address(0), shares);
        return true;
    }
}

interface IMigratorChef {
    // Take the current LP token address and return the new LP token address.
    // Migrator should have full access to the caller's LP token.
    function migrate(IERC20 token) external returns (IERC20);
}

// DAO code by BoringCrypto
// Token pool code from SushiSwap MasterChef V2, pioneered by Chef Nomi (I think) and improved by Keno Budde
contract DictatorDAO is ERC20, BoringBatchable, BoringOwnable {
    using BoringMath for uint256;
    using BoringMath128 for uint128;
    using SignedSafeMath for int256;
    using BoringERC20 for IERC20;

    string public constant symbol = "DIC";
    string public constant name = "Dictator DAO Token";
    uint8 public constant decimals = 18;
    uint256 public constant totalSupply = 100000000 * 1e18;

    uint256 immutable startTime;

    constructor() public {
        // Register founding time
        startTime = block.timestamp;

        // Mint all tokens and assign to the contract (no need for minting code after this + safe some gas)
        balanceOf[address(this)] = totalSupply;
        emit Transfer(address(0), address(this), totalSupply);
    }

    function _tokensPerWeek() internal view returns (uint256) {
        uint256 elapsed = (block.timestamp - startTime) / 7 days;
        return elapsed < 50 ? 1000000e18 : elapsed < 100 ? 500000e18 : elapsed < 150 ? 300000e18 : elapsed < 200 ? 200000e18 : 0;
    }

    function _tokensPerBlock() internal view returns (uint256) {
        uint256 elapsed = (block.timestamp - startTime) / 7 days;
        return elapsed < 50 ? 219780e14 : elapsed < 100 ? 109890e14 : elapsed < 150 ? 65934e14 : elapsed < 200 ? 43956e14 : 0;
    }

    event Deposit(address indexed user, uint256 indexed pid, uint256 amount, address indexed to);
    event Withdraw(address indexed user, uint256 indexed pid, uint256 amount, address indexed to);
    event EmergencyWithdraw(address indexed user, uint256 indexed pid, uint256 amount, address indexed to);
    event Harvest(address indexed user, uint256 indexed pid, uint256 amount);
    event LogPoolAddition(uint256 indexed pid, uint256 allocPoint, IERC20 indexed lpToken, IRewarder indexed rewarder);
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
    IERC20[] public lpToken;
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
    /// @param _lpToken Address of the LP ERC-20 token.
    /// @param _rewarder Address of the rewarder delegate.
    function addPool(
        uint256 allocPoint,
        IERC20 _lpToken,
        IRewarder _rewarder
    ) public onlyOwner {
        uint256 lastRewardBlock = block.number;
        totalAllocPoint = totalAllocPoint.add(allocPoint);
        lpToken.push(_lpToken);
        rewarder.push(_rewarder);

        poolInfo.push(PoolInfo({allocPoint: allocPoint.to64(), lastRewardBlock: lastRewardBlock.to64(), accTokensPerShare: 0}));
        emit LogPoolAddition(lpToken.length.sub(1), allocPoint, _lpToken, _rewarder);
    }

    /// @notice Update the given pool's tokens allocation point and `IRewarder` contract. Can only be called by the owner.
    /// @param _pid The index of the pool. See `poolInfo`.
    /// @param _allocPoint New AP of the pool.
    /// @param _rewarder Address of the rewarder delegate.
    /// @param overwrite True if _rewarder should be `set`. Otherwise `_rewarder` is ignored.
    function set(
        uint256 _pid,
        uint256 _allocPoint,
        IRewarder _rewarder,
        bool overwrite
    ) public onlyOwner {
        totalAllocPoint = totalAllocPoint.sub(poolInfo[_pid].allocPoint).add(_allocPoint);
        poolInfo[_pid].allocPoint = _allocPoint.to64();
        if (overwrite) {
            rewarder[_pid] = _rewarder;
        }
        emit LogSetPool(_pid, _allocPoint, overwrite ? _rewarder : rewarder[_pid], overwrite);
    }

    /// @notice Set the `migrator` contract. Can only be called by the owner.
    /// @param _migrator The contract address to set.
    function setMigrator(IMigratorChef _migrator) public onlyOwner {
        migrator = _migrator;
    }

    /// @notice Migrate LP token to another LP contract through the `migrator` contract.
    /// @param _pid The index of the pool. See `poolInfo`.
    function migrate(uint256 _pid) public {
        require(address(migrator) != address(0), "MasterChefV2: no migrator set");
        IERC20 _lpToken = lpToken[_pid];
        uint256 bal = _lpToken.balanceOf(address(this));
        _lpToken.approve(address(migrator), bal);
        IERC20 newLpToken = migrator.migrate(_lpToken);
        require(bal == newLpToken.balanceOf(address(this)), "MasterChefV2: migrated balance must match");
        lpToken[_pid] = newLpToken;
    }

    /// @notice View function to see pending tokens on frontend.
    /// @param _pid The index of the pool. See `poolInfo`.
    /// @param _user Address of user.
    /// @return pending tokens reward for a given user.
    function pendingTokens(uint256 _pid, address _user) external view returns (uint256 pending) {
        PoolInfo memory pool = poolInfo[_pid];
        UserInfo storage user = userInfo[_pid][_user];
        uint256 accTokensPerShare = pool.accTokensPerShare;
        uint256 lpSupply = lpToken[_pid].balanceOf(address(this));
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
            uint256 lpSupply = lpToken[pid].balanceOf(address(this));
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

        lpToken[pid].safeTransferFrom(msg.sender, address(this), amount);

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

        lpToken[pid].safeTransfer(to, amount);

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

        lpToken[pid].safeTransfer(to, amount);

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
        lpToken[pid].safeTransfer(to, amount);
        emit EmergencyWithdraw(msg.sender, pid, amount, to);
    }
}
