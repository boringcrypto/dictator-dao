const { expect } = require("chai")
const { createFixture } = require("./framework")

describe("DictatorDAO", function () {
    let fixture
    before(async function () {
        fixture = await createFixture(deployments, this, async (cmd) => {
            await cmd.deploy("dao", "DictatorDAO", this.bob.address)
            const tokenAddress = await this.dao.token()
            await cmd.attach("token", "DictatorToken", tokenAddress)
        })
    })

    beforeEach(async function () {
        cmd = await fixture()
    })

    it("Should do something", async function () {
        console.log(await this.token.DAO())
        console.log((await hre.ethers.provider.getBalance("0x9e6e344f94305d36eA59912b0911fE2c9149Ed3E")).toString())
    })
})
