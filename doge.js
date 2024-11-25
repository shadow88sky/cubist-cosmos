const cs = require('@cubist-labs/cubesigner-sdk')
const {
  JsonFileSessionManager,
} = require('@cubist-labs/cubesigner-sdk-fs-storage')
const axios = require('axios')
const bip39 = require('bip39')
const { BIP32Factory } = require('bip32')
const ecc = require('tiny-secp256k1')
const bip32 = BIP32Factory(ecc)
var bitcorelib = require('bitcore-lib')
const BigNumber = require('bignumber.js')
const bitcorelibdoge = require('bitcore-lib-doge')
const secp256k1 = require('secp256k1')

const mnemonicId =
  '0xcd3dac4e94c3b334d14ccf70debd9c05fec0659ab7a81a36a0af3742f25a1b84'
const oidcToken =
  'eyJhbGciOiJSUzI1NiIsImtpZCI6IjM2MjgyNTg2MDExMTNlNjU3NmE0NTMzNzM2NWZlOGI4OTczZDE2NzEiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhenAiOiI0Nzk0NjU3NjEzMTEtNWRhNmIyaWM3aW83b2RyOWpucmxkYWkyMDA0NnZrNHQuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJhdWQiOiI0Nzk0NjU3NjEzMTEtNWRhNmIyaWM3aW83b2RyOWpucmxkYWkyMDA0NnZrNHQuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiIxMTIzNzk1NjA2NjExOTIyNDE0MzciLCJoZCI6ImtubjMueHl6IiwiZW1haWwiOiJjaGVuLnh1QGtubjMueHl6IiwiZW1haWxfdmVyaWZpZWQiOnRydWUsIm5vbmNlIjoidGVzdG5vbmNlIiwibmJmIjoxNzMyNTM5OTU4LCJuYW1lIjoi5b6Q5pmoIiwicGljdHVyZSI6Imh0dHBzOi8vbGgzLmdvb2dsZXVzZXJjb250ZW50LmNvbS9hL0FDZzhvY0tkS1dQRnJ6ZVR4YVZvei1PbzNfclJFTVM3cVlkV3RwcTJ5MjFMUXlhYlBhWWVaZz1zOTYtYyIsImdpdmVuX25hbWUiOiLmmagiLCJmYW1pbHlfbmFtZSI6IuW-kCIsImlhdCI6MTczMjU0MDI1OCwiZXhwIjoxNzMyNTQzODU4LCJqdGkiOiI3OWEwOTdmMjNjOWVkZGE5ZTI0MWM3MWUwMTljMWMxM2JiMDY5NzM1In0.doCQpeH-2l68h4DaUdEPVAIZC5_aYc6yp7fraFSxr1vvCMdSkFnM5IpW9mlwtzoktTFT6RrIIrzI9QLa5XhBiIl0yzfZD_RPZyGHNWOtZhJdkKu7AsAjZZ0FWcWgIXIIvnOYEdso-UYewFrftlgreYskbrtcGUgkB4Bd3mPwx-leQohhAaoaoo-Xv5Y9X20nGQEZwKekgA2LJElwrE1BD3G-YfRUjI0dw_9LEaHFd4T7JbaQS8fpK4buPP5roO_19G7aEEmhaEY8qpOqTjWpmFZE-lujc-i0qLIXE4A0Us9TTmAEfNlJYOW3_vW-lDoGtLQoF8Td2KZpNjv15AxbzQ'

async function getUnspentUtxos(rpc, address) {
  const result = await axios.get(`${rpc}/address/${address}/?unspent=true`)
  return result.data
}

async function deriveKey(cubesigner, materialId, isDev = false) {
  const type = isDev ? cs.Secp256k1.DogeTest : cs.Secp256k1.Doge
  const path = isDev ? "m/44'/1'/0'/0/0" : "m/44'/3'/0'/0/0"
  const deriveResponse = await cubesigner
    .org()
    .deriveKey(type, path, materialId, {
      idempotent: true,
      policy: [cs.AllowRawBlobSigning],
    })
  return deriveResponse?.materialId
}

async function buildTx(from, to, rpcUrl, fee, amount, isDev = false) {
  const unspent = await getUnspentUtxos(rpcUrl, from)
  const unspentOutputs = unspent.map((tx) => ({
    address: from,
    txId: tx.mintTxid,
    outputIndex: tx.mintIndex,
    script: tx.script,
    satoshis: tx.value,
  }))
  const amountInBigStr = new BigNumber(amount)
    .times(new BigNumber(10).pow(8))
    .toFixed(0)
  const tx = new bitcorelibdoge.Transaction()
    .from(unspentOutputs)
    .to(to, Number(amountInBigStr))
    .fee(Number(fee))
    .change(from)
  return tx
}

async function getCubeSigner() {
  const cubesigner = await cs.CubeSignerClient.create(
    new JsonFileSessionManager(process.cwd() + '/user_session.json')
  )
  return cubesigner
}

async function getOidcClient(oidcToken, cubeClient, totpSecret) {
  const org = cubeClient.org()
  let oidcSessionResp = await cs.CubeSignerClient.createOidcSession(
    cubeClient.env,
    org.id,
    oidcToken,
    ['manage:*', 'sign:*', 'export:*'] // scopes for the session
  )
  if (oidcSessionResp.requiresMfa()) {
    if (!totpSecret) {
      throw new Error('totpSecret is required')
    }
    const mfaClient = await oidcSessionResp.mfaClient()
    const mfaId = oidcSessionResp?.mfaId()
    const status = await mfaClient
      .org()
      .getMfaRequest(mfaId)
      .totpApprove(authenticator.generate(totpSecret))
    const receipt = await status.receipt()
    oidcSessionResp = await oidcSessionResp.execWithMfaApproval(receipt)
  }
  return await cs.CubeSignerClient.create(oidcSessionResp.data())
}

async function bitDogeSign(tx, isDev = false) {
  const seed = await bip39.mnemonicToSeed('xxxxx')
  let root = bip32.fromSeed(seed)
  const path = isDev ? "m/44'/1'/0'/0/0" : "m/44'/3'/0'/0/0"
  const keyPair = root.derivePath(path)
  const privateKey = new bitcorelib.PrivateKey(
    keyPair.toWIF(),
    isDev ? bitcorelibdoge.Networks.testnet : bitcorelibdoge.Networks.mainnet
  )
  tx.sign(privateKey)
  console.log('bitcore-lib-doge sign success')
}

async function signTransactionByCubist(isDev = false) {
  const tx = await buildTx(
    'DGTEeHA8HKFy8xWKPiivdXWFQHaFw88X7e',
    'DF8u3AvhViYvfGmDtdS8PQDMu9CT9frrwc',
    'https://api.bitcore.io/api/DOGE/mainnet',
    '2000000',
    1,
    isDev
  )
  await bitDogeSign(tx)

  const cubesigner = await getCubeSigner()
  const oidcClient = await getOidcClient(oidcToken, cubesigner)
  const materialId = await deriveKey(cubesigner, mnemonicId)
  const type = isDev ? cs.Secp256k1.DogeTest : cs.Secp256k1.Doge
  const key = await oidcClient.org().getKeyByMaterialId(type, materialId)
  const publicKey = secp256k1.publicKeyConvert(
    Buffer.from(key.publicKey.slice(2), 'hex'),
    true
  )
  for (let index = 0; index < tx.inputs.length; index++) {
    const input = tx.inputs[index]
    const hashbuf = bitcorelibdoge.Transaction.Sighash.sighash(
      tx,
      bitcorelibdoge.crypto.Signature.SIGHASH_ALL,
      index,
      input.output.script
    )
    const sig = (
      await key.signBlob({
        message_base64: Buffer.from(hashbuf).toString('base64'),
      })
    )
      .data()
      .signature.slice(2)
    console.log(sig)
    const signatureBuffer = Buffer.from(sig.slice(2), 'hex')
    let r = signatureBuffer.slice(0, 32)
    let s = signatureBuffer.slice(32, 64)

    const signature = bitcorelibdoge.crypto.Signature(
      new bitcorelibdoge.crypto.BN(r.toString('hex'), 16),
      new bitcorelibdoge.crypto.BN(s.toString('hex'), 16)
    )
    signature.set({
      r: new bitcorelibdoge.crypto.BN(r.toString('hex'), 16),
      s: new bitcorelibdoge.crypto.BN(s.toString('hex'), 16),
      compressed: true,
      nhashtype: 1,
    })
    tx.applySignature(
      // error
      new bitcorelibdoge.Transaction.Signature({
        publicKey: new bitcorelibdoge.PublicKey(publicKey),
        prevTxId: input.prevTxId,
        outputIndex: input.outputIndex,
        inputIndex: index,
        signature: signature,
        sigtype: bitcorelibdoge.crypto.Signature.SIGHASH_ALL,
      })
    )
  }
}

signTransactionByCubist().then()
