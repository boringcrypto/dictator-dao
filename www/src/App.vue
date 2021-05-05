<template>
  <div>
    <img alt="Dictator DAO Logo" src="./assets/logo.jpeg" height="180" />
    <h1>Dictator DAO</h1>

    <p>
      Dictator DAO is an organization where the token holders democratically elect a 'dictator' to operate the protocol.
      Whenever the DAO isn't happy, they can simply elect a new 'dictator'.
    </p>
    <Web3 :info="web3">
      <template v-slot:none>
        No web3 provider was found. Please use MetaMask.
      </template>
      <template v-slot:connect>
        <button @click="web3.connect">Connect Metamask</button>
      </template>
      Name: {{ web3.name }}<br>
      Connected: {{ web3.connected }}<br>
      Address: {{ web3.address }}<br>
      ChainId: {{ web3.chainId }}<br>
      Block: {{ web3.block }}
    </Web3>
  </div>
</template>

<script lang="ts">
import { defineComponent, Ref, ref } from 'vue'
import Web3, { EmptyProviderInfo, ProviderInfo } from './components/Web3.vue'

export default defineComponent({
  name: 'App',
  components: {
    Web3
  },
  setup: () => {
    const web3: Ref<ProviderInfo> = ref(EmptyProviderInfo)
    return {
      web3
    }
  }
})
</script>

<style>
#app {
  font-family: Avenir, Helvetica, Arial, sans-serif;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
  text-align: center;
  color: #2c3e50;
  margin-top: 20px;
}
</style>
