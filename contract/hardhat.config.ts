import { task } from "hardhat/config";
import "@openzeppelin/hardhat-upgrades";
import "@nomicfoundation/hardhat-verify";
import "hardhat-contract-sizer";
import "hardhat-abi-exporter";
import "hardhat-gas-reporter";
import "hardhat-deploy";
import "@nomicfoundation/hardhat-ethers";
import "@nomicfoundation/hardhat-chai-matchers";
import "@typechain/hardhat";
import * as dotenv from "dotenv";
import * as fs from "fs";
import * as path from "path";

dotenv.config();

task("accounts", "Prints the list of accounts", async (taskArgs, hre) => {
  const accounts = await hre.ethers.getSigners();
  for (const account of accounts) {
    console.log(account.address);
  }
});

// Usage: npx hardhat verify-diploma --network polygon-amoy
// Tự động đọc địa chỉ contract và constructor args từ deployments/<network>.json
task("verify-diploma", "Verify DiplomaRegistry on Polygonscan", async (_, hre) => {
  const networkName = hre.network.name;
  const deploymentPath = path.join(__dirname, "deployments", networkName, "DiplomaRegistry.json");

  if (!fs.existsSync(deploymentPath)) {
    throw new Error(`Deployment file not found: ${deploymentPath}\nRun deploy first.`);
  }

  const deployment = JSON.parse(fs.readFileSync(deploymentPath, "utf-8"));
  const contractAddress = deployment.address;
  const { institutionName, schoolAdmin } = deployment.args
    ? { institutionName: deployment.args[0], schoolAdmin: deployment.args[1] }
    : {
        institutionName: process.env.INSTITUTION_NAME!,
        schoolAdmin:     process.env.SCHOOL_ADMIN_ADDRESS!,
      };

  console.log(`Verifying DiplomaRegistry at ${contractAddress}...`);
  console.log(`  institutionName : ${institutionName}`);
  console.log(`  schoolAdmin     : ${schoolAdmin}`);

  await hre.run("verify:verify", {
    address:              contractAddress,
    constructorArguments: [institutionName, schoolAdmin],
  });
});

const DUMMY_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const testnetPrivateKey = process.env.TESTNET_PRIVATE_KEY ?? DUMMY_KEY;
const mainnetPrivateKey = process.env.MAINNET_PRIVATE_KEY ?? DUMMY_KEY;

const reportGas = process.env.REPORT_GAS;

/**
 * @type import('hardhat/config').HardhatUserConfig
 */
module.exports = {
  networks: {
    // ─── Testnet ────────────────────────────────────────────────
    "polygon-amoy": {
      url: process.env.POLYGON_AMOY_RPC_URL || "https://rpc-amoy.polygon.technology",
      chainId: 80002,
      accounts: process.env.TESTNET_PRIVATE_KEY ? [testnetPrivateKey] : [],
      timeout: 40000,
    },

    // ─── Mainnet ────────────────────────────────────────────────
    "polygon": {
      url: process.env.POLYGON_MAINNET_RPC_URL || "https://polygon-rpc.com",
      chainId: 137,
      accounts: process.env.MAINNET_PRIVATE_KEY ? [mainnetPrivateKey] : [],
      timeout: 40000,
    },
  },

  solidity: {
    compilers: [
      {
        version: "0.8.28",
        settings: {
          evmVersion: "cancun",
          optimizer: {
            enabled: true,
            runs: 1000,
          },
          viaIR: true,
        },
      },
    ],
  },

  abiExporter: {
    path: "data/abi",
    runOnCompile: true,
    clear: true,
    flat: false,
    only: [],
    spacing: 4,
  },

  gasReporter: {
    enabled: reportGas === "1",
    currency: "USD",
    token: "MATIC",
    coinmarketcap: process.env.COINMARKETCAP_API_KEY,
  },

  contractSizer: {
    alphaSort: true,
    disambiguatePaths: false,
    runOnCompile: true,
  },

  etherscan: {
    // Etherscan API V2 — dùng 1 key duy nhất cho tất cả network
    apiKey: process.env.POLYGONSCAN_API_KEY!,
    customChains: [
      {
        network: "polygonAmoy",
        chainId: 80002,
        urls: {
          apiURL:     "https://api.etherscan.io/v2/api?chainid=80002",
          browserURL: "https://amoy.polygonscan.com",
        },
      },
      {
        network: "polygon",
        chainId: 137,
        urls: {
          apiURL:     "https://api.etherscan.io/v2/api?chainid=137",
          browserURL: "https://polygonscan.com",
        },
      },
    ],
  },

  sourcify: {
    enabled: false,
  },

  mocha: {
    timeout: 40000,
  },

  namedAccounts: {
    deployer: 0,
  },

  typechain: {
    outDir: "typechain",
    target: "ethers-v6",
  },
};