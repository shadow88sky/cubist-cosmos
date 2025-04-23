const cs = require('@cubist-labs/cubesigner-sdk')
const {
  JsonFileSessionManager,
} = require('@cubist-labs/cubesigner-sdk-fs-storage')
const { TronWeb, utils } = require('tronweb')
const { Signature, getBytesCopy } = require('ethers')

const PERMIT2_PERMIT_TYPE = {
  PermitDetails: [
    {
      name: 'token',
      type: 'address',
    },
    {
      name: 'amount',
      type: 'uint160',
    },
    {
      name: 'expiration',
      type: 'uint48',
    },
    {
      name: 'nonce',
      type: 'uint48',
    },
  ],
  PermitSingle: [
    {
      name: 'details',
      type: 'PermitDetails',
    },
    {
      name: 'spender',
      type: 'address',
    },
    {
      name: 'sigDeadline',
      type: 'uint256',
    },
  ],
}

const eip712Domain = {
  name: 'Permit2',
  chainId: 728126428,
  verifyingContract: 'TDJNTBi51CnnpCYYgi6GitoT4CJWrqim2G',
}

const permitSingle = {
  details: {
    token: '0xa614f803b6fd780986a42c78ec9c7f77e6ded13c',
    amount: '87996',
    expiration: 0,
    nonce: 0,
  },
  spender: '0xbde814ebd17a0b25c39ee16a8b2ff48d1628e503',
  sigDeadline: 1745381314,
}

async function signFromTronWeb() {
  const tronWeb = new TronWeb({
    //   fullHost: 'https://api.trongrid.io', // mainnet
    //   fullHost: 'https://api.shasta.trongrid.io', // testnet
    fullHost: 'https://nile.trongrid.io',
    privateKey: 'xxxx',
  })

  const tronWebSig = await tronWeb.trx._signTypedData(
    eip712Domain,
    PERMIT2_PERMIT_TYPE,
    permitSingle
  )
  console.log('\ntronWeb signature: \n', tronWebSig)
}

async function signFromCubist() {
  const message = tronWeb.utils._signTypedData.hash(
    eip712Domain,
    PERMIT2_PERMIT_TYPE,
    permitSingle
  )
  const oidcClient = await cs.CubeSignerClient.create(userInfo)
  const key = await getKey(oidcClient, mnemonicId, materialId)
  const signature = await key.signBlob({
    message_base64: Buffer.from(getBytesCopy(message)).toString('base64'),
  })
  const buf = Buffer.from(signature.data().signature.slice(2), 'hex')
  const r = buf.subarray(0, 32)
  const s = buf.subarray(32, 64)
  const v = buf[64]
  const rHex = '0x' + r.toString('hex')
  const sHex = '0x' + s.toString('hex')
  return Signature.from({
    r: rHex,
    s: sHex,
    v: v,
  }).serialized
}
