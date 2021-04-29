const { expect } = require("chai");

describe("DictatorDAO", function() {
  it("Should do something", async function() {
    const DAO = await ethers.getContractFactory("DictatorDAO");
    const dao = await DAO.deploy();
    
    await dao.deployed();
  });
});
