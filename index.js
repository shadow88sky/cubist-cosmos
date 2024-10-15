const cs = require('@cubist-labs/cubesigner-sdk')
const {
  JsonFileSessionManager,
} = require('@cubist-labs/cubesigner-sdk-fs-storage')
const { StargateClient } = require('@cosmjs/stargate')
const { MsgSend } = require('cosmjs-types/cosmos/bank/v1beta1/tx')
const {
  Fee,
  TxBody,
  TxRaw,
  AuthInfo,
} = require('cosmjs-types/cosmos/tx/v1beta1/tx')
const {
  DirectSecp256k1HdWallet,
  makeSignBytes,
} = require('@cosmjs/proto-signing')
const { PubKey } = require('cosmjs-types/cosmos/crypto/secp256k1/keys')
const secp256k1 = require('secp256k1')
const { SignMode } = require('cosmjs-types/cosmos/tx/signing/v1beta1/signing')
const { coins } = require('@cosmjs/amino')
const { sha256 } = require('@cosmjs/crypto')
const { createHash } = require('crypto')
const { authenticator } = require('otplib')

const senderAddress = 'cosmos1myw6h67f428q7yxjx52xkam...' // sender address
const toAddress = 'cosmos182q9qjpf22encpsauxm7wqkl5fzsu...' // to Address
const token = '' // oidc token
const mnemonic = 'xxxxx'
const pubkey =
  '044c7eb0be821ab51b9e136fb0cb1e1970c95b9cd3e79d09cf9a8ef9b011cac11e8ea8b8c095f2b3916a7c70719ecd15afa6ee2afcfe602c3cb5333e8dea2bfcac' // cubist sender's publickey
const mnemonic_id =
  '0xcfe285c88a666292cd665284c177e359d0c889c638a22e213b232f78941d24e8' // cubist mnemonic id

// sendTx().then()
// sendTxByCubist().then()

async function createSignDoc() {
  const endpoint = 'https://cosmos-rpc.quickapi.com:443'
  const client = await StargateClient.connect(endpoint)
  const account = await client.getAccount(senderAddress)
  const accountNumber = account.accountNumber
  const sequence = account.sequence

  const proto = [
    {
      typeUrl: '/cosmos.bank.v1beta1.MsgSend',
      value: MsgSend.encode({
        fromAddress: senderAddress,
        toAddress: toAddress,
        amount: [
          {
            denom: 'uatom',
            amount: '1000',
          },
        ],
      }).finish(),
    },
  ]
  const tx = TxBody.encode(
    TxBody.fromPartial({
      messages: proto,
      memo: 'Sent',
    })
  ).finish()

  const signDoc = {
    bodyBytes: tx,
    authInfoBytes: AuthInfo.encode({
      signerInfos: [
        {
          publicKey: {
            typeUrl: '/cosmos.crypto.secp256k1.PubKey',
            value: PubKey.encode({
              // key: (await wallet.getAccounts())[0].pubkey,
              key: secp256k1.publicKeyConvert(Buffer.from(pubkey, 'hex'), true),
            }).finish(),
          },
          modeInfo: {
            single: {
              mode: SignMode.SIGN_MODE_DIRECT,
            },
            multi: undefined,
          },
          sequence: BigInt(sequence),
        },
      ],
      fee: Fee.fromPartial({
        amount: coins(Number(11100), 'uatom'),
        gasLimit: BigInt('222000'),
      }),
    }).finish(),
    chainId: 'cosmoshub-4',
    accountNumber: BigInt(accountNumber),
  }
  return signDoc
}

async function sendTx() {
  const endpoint = 'https://cosmos-rpc.quickapi.com:443'
  const client = await StargateClient.connect(endpoint)
  const wallet = await DirectSecp256k1HdWallet.fromMnemonic(mnemonic)
  const signDoc = await createSignDoc()
  const ret = await wallet.signDirect(senderAddress, signDoc)
  const signedTx = TxRaw.encode({
    bodyBytes: signDoc.bodyBytes,
    authInfoBytes: signDoc.authInfoBytes,
    signatures: [Buffer.from(ret.signature.signature, 'base64')],
  }).finish()
  const txHash = await client.broadcastTx(signedTx)
  console.log(txHash)
}

async function sendTxByCubist() {
  const endpoint = 'https://cosmos-rpc.quickapi.com:443'
  const client = await StargateClient.connect(endpoint)
  const signDoc = await createSignDoc()
  const signMessage = await signTransactionByCubist(
    mnemonic_id,
    token,
    signDoc,
    'GBKBP2WQ4TMHKO67UQLVMYTOOPO2QOQG'
  )
  const tx = TxRaw.encode({
    bodyBytes: signDoc.bodyBytes,
    authInfoBytes: signDoc.authInfoBytes,
    signatures: [Buffer.from(signMessage, 'hex')],
  }).finish()
  const result = await client.broadcastTx(tx)
  console.log(result)
}

async function getCubeSigner() {
  const cubesigner = await cs.CubeSignerClient.create(
    new JsonFileSessionManager(process.cwd() + '/user_session.json')
  )
  return cubesigner
}

async function signTransactionByCubist(mnemonicId, oidcToken, signDoc, secret) {
  const cubesigner = await getCubeSigner()
  const oidcClient = await getOidcClient(oidcToken, cubesigner, secret)
  const materialId = await deriveKey(cubesigner, mnemonicId)
  const key = await oidcClient
    .org()
    .getKeyByMaterialId(cs.Secp256k1.Cosmos, materialId)
  const bytes = makeSignBytes(signDoc)
  const hash = sha256(bytes)
  let sig = (
    await key.signBlob({
      message_base64: createHash('sha256').update(hash).digest('base64'),
    })
  ).data().signature
  return sig.substring(2, sig.length)
}

async function deriveKey(cubesigner, materialId) {
  const deriveResponse = await cubesigner
    .org()
    .deriveKey(cs.Secp256k1.Cosmos, "m/44'/118'/0'/0/0", materialId, {
      idempotent: true,
      policy: [cs.AllowRawBlobSigning],
    })
  return deriveResponse?.materialId
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
