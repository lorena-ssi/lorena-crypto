const LorenaCrypto = require('../src/index')
const chai = require('chai')
  .use(require('chai-as-promised'))
const assert = chai.assert

const message = 'Hello World'
const password = 'password random'

let alice
let signature = false
let msgEncrypted = false
let rnd = false
const crypto = new LorenaCrypto(true)

describe('LorenaCrypto', function () {
  // Keypairs.
  describe('1. KeyPair generation: ', () => {
    it('Should create a new KeyPair: ', async () => {
      alice = await crypto.newKeyPair()
      assert.isNotEmpty(alice.mnemonic)
      const mnemArray = alice.mnemonic.split(' ')
      assert.equal(mnemArray.length, 12)

      assert.isNotEmpty(alice.keyPair.publicKey)
      assert.equal(alice.keyPair.publicKey.length, 32)
      assert.isNotEmpty(alice.keyPair.secretKey)
      assert.equal(alice.keyPair.secretKey.length, 64)
    })
  })

  describe('2. Hash Blake2: ', () => {
    it('Should hash a String: ', async () => {
      const result = await crypto.blake2('Hello world')
      assert.isNotEmpty(result)
    })
  })

  describe('3. Random: ', () => {
    it('Should create a random String: ', async () => {
      rnd = await crypto.random()
      assert.isNotEmpty(rnd)
      assert.equal(rnd.length, 32)
      rnd = await crypto.random(16)
      assert.equal(rnd.length, 16)
      rnd = await crypto.random(8)
      assert.equal(rnd.length, 8)
    })

    it('Should create a random PIN: ', async () => {
      rnd = await crypto.randomPin()
      assert.isNotEmpty(rnd)
      assert.equal(rnd.length, 6)
      rnd = await crypto.randomPin(4)
      assert.equal(rnd.length, 4)
    })
  })

  describe('4. Signatures: ', () => {
    it('Should create a new Signature: ', async () => {
      signature = await crypto.signMessage(message, alice.keyPair)
      assert.isNotEmpty(signature)
    })

    it('Should Check the Signature: ', async () => {
      const check = await crypto.checkSignature(message, signature, alice.keyPair.publicKey)
      assert.equal(check, true)
    })
  })

  // Encryption.
  describe('5. Encryption: ', () => {
    it('Should encrypt (symmetric) a message: ', async () => {
      msgEncrypted = await crypto.encryptSymmetric(password, message)
      assert.isNotEmpty(msgEncrypted.encrypted)
      assert.isNotEmpty(msgEncrypted.nonce)
    })

    it('Should decrypt (symmetric) a message: ', async () => {
      const msg = await crypto.decryptSymmetric(password, msgEncrypted)
      assert.equal(msg, message)
    })
  })
  /*

    it('Should NOT decrypt (symmetric) a message with wrong password: ', async () => {
      const msg = await z.decryptSymmetric('badpassword', msgEncrypted)
      assert.equal(msg.message, undefined)
      assert.equal(msg.header, undefined)
    })

    it('Should encrypt (asymmetric) a message: ', async () => {
      msgEncrypted = await z.encryptAsymmetric('Alice', aliceKeypair, 'Bob', bobPublic, message)
      assert.isNotEmpty(msgEncrypted.secret_message)
      assert.isNotEmpty(msgEncrypted.secret_message.iv)
      assert.isNotEmpty(msgEncrypted.secret_message.header)
      assert.isNotEmpty(msgEncrypted.secret_message.text)
      assert.isNotEmpty(msgEncrypted.secret_message.checksum)
    })

    it('Should decrypt a  (asymmetric) message: ', async () => {
      const msg = await z.decryptAsymmetric('Alice', alicePublic, 'Bob', bobKeypair, msgEncrypted)
      assert.equal(msg.message, message)
    })
  })
*/
})
