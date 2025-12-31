import json
from typing import Any, Dict

from web3 import Web3

# Minimal ABIs for Phase 3 support
AAVE_V3_POOL_ABI = json.loads('''[
    {"inputs":[{"internalType":"address","name":"asset","type":"address"},{"internalType":"uint256","name":"amount","type":"uint256"},{"internalType":"address","name":"onBehalfOf","type":"address"},{"internalType":"uint16","name":"referralCode","type":"uint16"}],"name":"supply","outputs":[],"stateMutability":"nonpayable","type":"function"},
    {"inputs":[{"internalType":"address","name":"asset","type":"address"},{"internalType":"uint256","name":"amount","type":"uint256"},{"internalType":"uint256","name":"interestRateMode","type":"uint256"},{"internalType":"uint16","name":"referralCode","type":"uint16"},{"internalType":"address","name":"onBehalfOf","type":"address"}],"name":"borrow","outputs":[],"stateMutability":"nonpayable","type":"function"},
    {"inputs":[{"internalType":"address","name":"user","type":"address"}],"name":"getUserAccountData","outputs":[{"internalType":"uint256","name":"totalCollateralBase","type":"uint256"},{"internalType":"uint256","name":"totalDebtBase","type":"uint256"},{"internalType":"uint256","name":"availableBorrowsBase","type":"uint256"},{"internalType":"uint256","name":"currentLiquidationThreshold","type":"uint256"},{"internalType":"uint256","name":"ltv","type":"uint256"},{"internalType":"uint256","name":"healthFactor","type":"uint256"}],"stateMutability":"view","type":"function"}
]''')

# Mapping of Chain ID -> Aave V3 Pool Address
AAVE_V3_POOLS = {
    1: Web3.to_checksum_address("0x87870B2ec3Ac922202c4a1585060401062f689e4"), # Ethereum Mainnet
    8453: Web3.to_checksum_address("0xA238Dd80C259a72e81d7e4674A963912f6711824"), # Base Mainnet
    11155111: Web3.to_checksum_address("0x6Ae433fd17A4f06c5683885116FAC621be55A3E5"), # Sepolia (example)
    84532: Web3.to_checksum_address("0x07eA79F68B23aD39400263f9611D6f43274619B0") # Base Sepolia (example)
}

class AaveV3Client:
    def __init__(self, w3: Web3, chain_id: int):
        self.w3 = w3
        self.chain_id = chain_id
        self.pool_address = AAVE_V3_POOLS.get(chain_id)
        if not self.pool_address:
            raise ValueError(f"Aave V3 Pool address not found for chain ID {chain_id}")
        self.pool = self.w3.eth.contract(address=self.pool_address, abi=AAVE_V3_POOL_ABI)

    def build_supply_tx(self, asset: str, amount_wei: int, on_behalf_of: str) -> Dict[str, Any]:
        return self.pool.functions.supply(
            Web3.to_checksum_address(asset),
            amount_wei,
            Web3.to_checksum_address(on_behalf_of),
            0 # referralCode
        ).build_transaction({
            "from": Web3.to_checksum_address(on_behalf_of),
            "gas": 300000 # Stub gas limit
        })

    def build_borrow_tx(self, asset: str, amount_wei: int, on_behalf_of: str, rate_mode: int = 2) -> Dict[str, Any]:
        """
        rate_mode: 1 for stable, 2 for variable.
        """
        return self.pool.functions.borrow(
            Web3.to_checksum_address(asset),
            amount_wei,
            rate_mode,
            0, # referralCode
            Web3.to_checksum_address(on_behalf_of)
        ).build_transaction({
            "from": Web3.to_checksum_address(on_behalf_of),
            "gas": 400000 # Stub gas limit
        })

    def get_user_data(self, user_address: str) -> Dict[str, Any]:
        data = self.pool.functions.getUserAccountData(Web3.to_checksum_address(user_address)).call()
        return {
            "total_collateral_base": data[0],
            "total_debt_base": data[1],
            "available_borrows_base": data[2],
            "liquidation_threshold": data[3],
            "ltv": data[4],
            "health_factor": data[5] / 10**18 # Health factor is 10^18 decimals
        }
