# @version 0.3.10
"""
SYNTHETIC Vyper contract mirroring Curve Vyper-era vulnerable pool
patterns. Used to test SELF's Vyper detectors.

Bugs intentionally embedded:
  1. add_liquidity() — no @nonreentrant while calling `token.transfer`
  2. withdraw() — uses unsafe `send()` for ETH (2200 gas limit)
  3. emergency_withdraw() — missing access control (no msg.sender check)
  4. lp_token public(uint256) — read-only reentrancy surface
  5. swap() — unchecked return value from `raw_call`
  6. reset_ownership() — uses selfdestruct (no longer in 0.3.10, but pattern)
  7. division by zero in price_oracle() (when reserves == 0)
"""
from ethereum.ercs import IERC20

interface CurvePool:
    def add_liquidity(amounts: uint256[N_COINS], min_lp: uint256) -> uint256: nonpayable
    def remove_liquidity(_amount: uint256, i: int128) -> uint256: nonpayable


N_COINS: constant(uint256) = 3

owner: public(address)
fee: uint256 = 30  # basis points
is_paused: bool = False
total_supply: uint256
balance_of: HashMap[address, uint256]
allowance: HashMap[address, HashMap[address, uint256]]

token: IERC20


@external
def __init__(_token: address, _owner: address):
    self.token = IERC20(_token)
    self.owner = _owner


@external
@view
def get_virtual_price() -> uint256:
    # No zero-reserve guard — division by zero when pool empty
    return 10**18 * self.total_supply // self.token.balanceOf(self)


@external
@payable
def deposit():
    # BUG: missing @nonreentrant, transfers tokens before updating state
    amount: uint256 = msg.value
    self.token.transfer(msg.sender, amount)  # external call BEFORE state update
    self.balance_of[msg.sender] += amount
    self.total_supply += amount


@external
def withdraw(to: address, amount: uint256):
    # BUG: uses .send() which forwards only 2300 gas and ignores failure
    self.balance_of[msg.sender] -= amount
    self.total_supply -= amount
    success: bool = send(to, amount)
    # Bug: success is never checked — silent ether loss


@external
def emergency_withdraw(amount: uint256):
    # BUG: no msg.sender == self.owner check — anyone can drain
    self.balance_of[msg.sender] -= amount
    self.total_supply -= amount
    raw_call(msg.sender, b"", value=amount)


@external
def swap(i: int128, j: int128, dx: uint256, min_dy: uint256):
    # BUG: raw_call return value unchecked
    data: Bytes[32] = _abi_encode(msg.sender, dx, method_id=method_id("transfer(address,uint256)"))
    raw_call(self.token.address, data, max_outsize=32)


@external
def reset_ownership(new_owner: address):
    # BUG: ownership can be reset to address(0) — losing admin
    assert new_owner != empty(address), "zero"
    self.owner = new_owner


@external
@view
def lp_token() -> uint256:
    # Read-only reentrancy surface — view fn reads balance
    return self.token.balanceOf(self)
