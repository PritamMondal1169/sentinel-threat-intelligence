import { HardhatUserConfig } from "hardhat/config";
import "@nomicfoundation/hardhat-toolbox";

const { RPC_URL, CHAIN_PRIVATE_KEY } = process.env; // testnet-only wallet, never a wallet with real funds
const config: HardhatUserConfig = {
  solidity: "0.8.24",
  networks: {
    localhost: { url: "http://127.0.0.1:8545" },
    ...(RPC_URL && CHAIN_PRIVATE_KEY ? { sepolia: { url: RPC_URL, accounts: [CHAIN_PRIVATE_KEY] } } : {}),
  },
};
export default config;
