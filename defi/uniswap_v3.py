import json

# Chain ID Constants
ETHEREUM = 1
BASE = 8453
ARBITRUM = 42161
OPTIMISM = 10

# Minimal ABIs for Uniswap V3 Support
UNI_V3_MANAGER_ABI = json.loads('''[
    {"inputs":[{"components":[{"internalType":"address","name":"token0","type":"address"},{"internalType":"address","name":"token1","type":"address"},{"internalType":"uint24","name":"fee","type":"uint24"},{"internalType":"int24","name":"tickLower","type":"int24"},{"internalType":"int24","name":"tickUpper","type":"int24"},{"internalType":"uint256","name":"amount0Desired","type":"uint256"},{"internalType":"uint256","name":"amount1Desired","type":"uint256"},{"internalType":"uint256","name":"amount0Min","type":"uint256"},{"internalType":"uint256","name":"amount1Min","type":"uint256"},{"internalType":"address","name":"recipient","type":"address"},{"internalType":"uint256","name":"deadline","type":"uint256"}],"internalType":"struct INonfungiblePositionManager.MintParams","name":"params","type":"tuple"}],"name":"mint","outputs":[{"internalType":"uint256","name":"tokenId","type":"uint256"},{"internalType":"uint128","name":"liquidity","type":"uint128"},{"internalType":"uint256","name":"amount0","type":"uint256"},{"internalType":"uint256","name":"amount1","type":"uint256"}],"stateMutability":"payable","type":"function"},
    {"inputs":[{"components":[{"internalType":"uint256","name":"tokenId","type":"uint256"},{"internalType":"address","name":"recipient","type":"address"},{"internalType":"uint128","name":"amount0Max","type":"uint128"},{"internalType":"uint128","name":"amount1Max","type":"uint128"}],"internalType":"struct INonfungiblePositionManager.CollectParams","name":"params","type":"tuple"}],"name":"collect","outputs":[{"internalType":"uint256","name":"amount0","type":"uint256"},{"internalType":"uint256","name":"amount1","type":"uint256"}],"stateMutability":"payable","type":"function"}
]''')

# Mapping of Chain ID -> Uniswap V3 NonfungiblePositionManager
NONFUNGIBLE_POSITION_MANAGER = {
    ETHEREUM: "0xC36442b4a4522E871399CD717aBDD847Ab11FE88",
    BASE: "0x03a520b32C04BF3bEEf7BEb72E919cf822EdC2f9",
    ARBITRUM: "0xC36442b4a4522E871399CD717aBDD847Ab11FE88",
    OPTIMISM: "0xC36442b4a4522E871399CD717aBDD847Ab11FE88",
}


class UniswapV3Client:
    def __init__(self, w3, chain_id: int):
        self.w3 = w3
        self.chain_id = chain_id
        self.manager_address = NONFUNGIBLE_POSITION_MANAGER.get(chain_id)
        if self.manager_address:
            self.manager = w3.eth.contract(address=self.manager_address, abi=UNI_V3_MANAGER_ABI)
        else:
            self.manager = None

    def mint_position(self, token0: str, token1: str, fee: int, amount0: int, amount1: int, recipient: str) -> dict:
        """
        Build a transaction to mint a new position (add liquidity).
        NOTE: This is a simplified example. In production, tick calculation is complex.
        """
        if not self.manager:
            raise ValueError(f"Uniswap V3 not supported on chain {self.chain_id}")

        # Params for MintParams struct
        # (token0, token1, fee, tickLower, tickUpper, amount0Desired, amount1Desired, amount0Min, amount1Min, recipient, deadline)
        params = (
            token0,
            token1,
            fee,
            -887272,  # min tick (full range) - illustrative only
            887272,   # max tick (full range)
            amount0,
            amount1,
            0,        # min0 (slippage protection omitted for brevity)
            0,        # min1
            recipient,
            9999999999 # deadline
        )
        
        return self.manager.functions.mint(params).build_transaction({
            "from": recipient,
            "nonce": self.w3.eth.get_transaction_count(recipient),
            "gas": 500000,
            "gasPrice": self.w3.eth.gas_price
        })
