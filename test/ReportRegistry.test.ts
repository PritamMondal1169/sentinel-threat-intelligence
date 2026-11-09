import { expect } from "chai";
import { ethers } from "hardhat";

describe("ReportRegistry", () => {
  const id = ethers.id("report-1"), h1 = ethers.id("content-1"), h2 = ethers.id("content-2");
  async function deploy() { return (await ethers.getContractFactory("ReportRegistry")).deploy(); }

  it("commits a first version", async () => {
    const r = await deploy(); await r.commit(id, h1, 1);
    const c = await r.latest(id);
    expect(c.contentHash).to.equal(h1); expect(c.version).to.equal(1); expect(c.prevHash).to.equal(ethers.ZeroHash);
  });
  it("chains a second version to the first", async () => {
    const r = await deploy(); await r.commit(id, h1, 1); await r.commit(id, h2, 1);
    expect((await r.getVersion(id, 2)).prevHash).to.equal(h1); expect(await r.versionCount(id)).to.equal(2);
  });
  it("rejects updates from a non-owner", async () => {
    const [a, b] = await ethers.getSigners(); const r = await deploy();
    await r.connect(a).commit(id, h1, 1);
    await expect(r.connect(b).commit(id, h2, 1)).to.be.revertedWith("not owner");
  });
  it("reverts for unknown reports and bad versions", async () => {
    const r = await deploy();
    await expect(r.latest(id)).to.be.revertedWith("unknown report");
    await expect(r.getVersion(id, 1)).to.be.revertedWith("bad version");
  });
});
