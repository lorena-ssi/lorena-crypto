'use strict'

const { mnemonicGenerate, mnemonicToSeed, naclDecrypt, naclEncrypt } = require('@polkadot/util-crypto')
const { stringToU8a, u8aConcat, u8aToHex, hexToString } = require('@polkadot/util')
const { randomAsU8a, naclKeypairFromSeed, naclSign, naclVerify, blake2AsHex } = require('@polkadot/util-crypto')

/**
 * Javascript Class to interact with Zenroom.
 */
module.exports = class LorenaCrypto {
  /**
   * Creates a new keypair.
   *
   * @returns {Promise} Return a promise with the execution of the creation.
   */
  async newKeyPair () {
    return new Promise((resolve) => {
      const mnemonic = mnemonicGenerate()
      const keyPair = naclKeypairFromSeed(mnemonicToSeed(mnemonic))
      resolve({ mnemonic, keyPair })
    })
  }

  /**
   * Creates a new keypair.
   *
   * @param {string} name  Holder of the keypair.
   * @param {*} keys to create
   * @returns {Promise} Return a promise with the execution of the creation.
   */
  async publicKey (name, keys) {
    return new Promise((resolve) => {
      resolve(true)
    })
  }

  /**
   * Encrypts (symmetric) a message with a keypair.
   *
   * @param {string} password Password to encrypt the message
   * @param {string} message Message to be encrypted
   * @param {string} header Header to be included
   * @returns {Promise} Return a promise with the execution of the encryption.
   */
  async encryptSymmetric (password, message) {
    return new Promise((resolve) => {
      let secret = stringToU8a(password)
      secret = u8aConcat(secret, new Uint8Array(32 - secret.length))
      const messagePreEncryption = stringToU8a(message)
      const noncePreEncryption = randomAsU8a(24)

      // Encrypt the message
      const result = naclEncrypt(messagePreEncryption, secret, noncePreEncryption)

      // Show contents of the encrypted message
      resolve(result)
    })
  }

  /**
   * Encrypts (symmetric) a message with a keypair.
   *
   * @param {string} password Password to decrypt the message
   * @param {Object} msgEncrypted Message to be decrypted
   * @returns {Promise} Return a promise with the execution of the encryption.
   */
  async decryptSymmetric (password, msgEncrypted) {
    return new Promise((resolve) => {
      let secret = stringToU8a(password)
      secret = u8aConcat(secret, new Uint8Array(32 - secret.length))
      const messageDecrypted = naclDecrypt(msgEncrypted.encrypted, msgEncrypted.nonce, secret)
      resolve(hexToString(u8aToHex(messageDecrypted)))
    })
  }

  /**
   * Signs a message with a keypair.
   *
   * @param {string} message Message to be signed
   * @param {object} secretKey Keypair for the signer (Zencode format)
   * @returns {Promise} Returns a promise with the execution of the signature.
   */
  async signMessage (message, secretKey) {
    return new Promise((resolve) => {
      const messageSignature = naclSign(message, secretKey)
      resolve(messageSignature)
    })
  }

  /**
   * Checks signature of a message.
   *
   * @param {string} message Message signed..
   * @param {object} signature Signature of the message.
   * @param {string} publicKey Public Key of the signature
   * @returns {Promise} Returns a promise with the execution of the signature.
   */
  async checkSignature (message, signature, publicKey) {
    return new Promise((resolve) => {
      const isValidSignature = naclVerify(message, signature, publicKey)
      resolve(isValidSignature)
    })
  }

  /**
   * Create a Random string
   *
   * @param {number} length Length of the random string
   * @returns {Promise} Return a promise with the execution of the creation.
   */
  async random (length = 32) {
    return new Promise((resolve) => {
      const rnd = hexToString(u8aToHex(randomAsU8a(length * 2)))
      resolve(rnd.slice(0, length))
    })
  }

  /**
   * Creates a random Pin
   *
   * @param {number} length Length of the random PIN
   * @returns {Promise} Return a promise with the execution of the creation.
   */
  async randomPin (length = 6) {
    return new Promise((resolve) => {
      const rnd = randomAsU8a(length)
      resolve(rnd.slice(0, length))
    })
  }

  /**
   * Create a Hash
   *
   * @param {string} source to be hashed
   * @returns {Promise} Return a promise with the execution of the creation.
   */
  async blake2 (source) {
    return new Promise((resolve) => {
      resolve(blake2AsHex(source))
    })
  }
}
