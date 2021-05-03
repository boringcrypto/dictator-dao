const {
    BigNumber,
    utils: { keccak256, defaultAbiCoder, toUtf8Bytes, solidityPack },
} = require("ethers")
const contracts = {}

function e10(decimals = 18) {
    return BigNumber.from("10").pow(decimals)
}

function BN(amount, decimals = 18) {
    return BigNumber.from(amount).mul(e10(decimals))
}

function addr(address) {
    if (typeof address == "object" && address.address) {
        address = address.address
    }
    return address
}

function addContract(thisObject, name, contract) {
    thisObject[name] = contract
    contract.thisName = name
    contracts[contract.address] = contract
}

async function createFixture(deployments, thisObject, stepsFunction) {
    return deployments.createFixture(async ({ deployments, getNamedAccounts, ethers }, options) => {
        const { deployer } = await getNamedAccounts()

        thisObject.signers = await ethers.getSigners()
        addContract(thisObject, "alice", thisObject.signers[0])
        addContract(thisObject, "bob", thisObject.signers[1])
        addContract(thisObject, "carol", thisObject.signers[2])
        addContract(thisObject, "dirk", thisObject.signers[3])
        addContract(thisObject, "erin", thisObject.signers[4])
        addContract(thisObject, "fred", thisObject.signers[5])
        thisObject.alicePrivateKey = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
        thisObject.bobPrivateKey = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
        thisObject.carolPrivateKey = "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a"

        const getContractFunction = async function (contract_name) {
            thisObject[contract_name] = await ethers.getContractFactory(contract_name)
            thisObject[contract_name].thisObject = thisObject
            thisObject[contract_name].new = async function (name, ...params) {
                let newContract = await thisObject[contract_name].deploy(...params)
                await newContract.deployed()
                newContract.factory = thisObject[contract_name]
                addContract(thisObject, name, newContract)
                return newContract
            }
            thisObject[contract_name].at = function (name, address) {
                let newContract = thisObject[contract_name].attach(address)
                newContract.factory = thisObject[contract_name]
                addContract(thisObject, name, newContract)
                return newContract
            }
            return thisObject[contract_name]
        }

        const deployFunction = async function (var_name, contract_name, ...params) {
            await getContractFunction(contract_name)
            const contract = await thisObject[contract_name].new(var_name, ...params)
            return contract
        }

        const attachFunction = async function (var_name, contract_name, address) {
            await getContractFunction(contract_name)
            const contract = thisObject[contract_name].at(var_name, address)
            return contract
        }

        const cmd = {
            getContract: getContractFunction,
            deploy: deployFunction,
            attach: attachFunction
        }

        await stepsFunction(cmd)
        return cmd
    })
}

module.exports = {
    e10,
    BN,
    addr,
    createFixture
}
