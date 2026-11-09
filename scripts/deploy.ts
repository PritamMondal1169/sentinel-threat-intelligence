import { ethers } from "hardhat";
import { writeFileSync } from "fs";

async function main() {
  const registry = await (await ethers.getContractFactory("ReportRegistry")).deploy();
  await registry.waitForDeployment();
  const address = await registry.getAddress();
  writeFileSync("deployments.json", JSON.stringify({ network: (await ethers.provider.getNetwork()).name, address }, null, 2));
  console.log("ReportRegistry deployed to", address);
}
main().catch((e) => { console.error(e); process.exit(1); });
