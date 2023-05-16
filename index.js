const nacl = require('tweetnacl');
const { Buffer } = require('buffer');

// generate solana keypair
function generateSolanaKeyPair() {
  const keyPair = nacl.sign.keyPair();
  const publicKey = keyPair.publicKey;
  const privateKey = keyPair.secretKey;
  const publicKeyString = Buffer.from(publicKey).toString('base64');
  const privateKeyString = Buffer.from(privateKey).toString('base64');
  return { publicKey: publicKeyString, privateKey: privateKeyString };
}

const keyPair = generateSolanaKeyPair();
console.log('Solana public key:', keyPair.publicKey);
console.log('Solana private key:', keyPair.privateKey);

// sign(priv, data)
function signData(privateKey, data) {
  const privateKeyBytes = Buffer.from(privateKey, 'base64');
  const signatureBytes = nacl.sign.detached(Buffer.from(data), privateKeyBytes);
  const signature = Buffer.from(signatureBytes).toString('base64');
  return signature;
}

// Function to verify data against a public key and signature
function verifyData(publicKey, data, signature) {
  const publicKeyBytes = Buffer.from(publicKey, 'base64');
  const signatureBytes = Buffer.from(signature, 'base64');
  const isSignatureValid = nacl.sign.detached.verify(Buffer.from(data), signatureBytes, publicKeyBytes);
  return isSignatureValid;
}

let data = 'data to be signed';
let signature = signData(keyPair.privateKey, data);
console.log('signature:' + signature);
console.log('verify data & signature: ' + verifyData(keyPair.publicKey, data, signature));

// Function to encrypt data with a public key
function encryptWithPublicKey(publicKey, data) {
  const publicKeyBytes = Buffer.from(publicKey, 'base64');
  const nonce = nacl.randomBytes(nacl.box.nonceLength);
  const encryptedBytes = nacl.box(Buffer.from(data), nonce, publicKeyBytes, nacl.box.keyPair().secretKey);
  const encryptedMessage = Buffer.concat([nonce, encryptedBytes]);
  const encryptedData = encryptedMessage.toString('base64');
  return encryptedData;
}

// Function to decrypt data with a private key
function decryptWithPrivateKey(privateKey, encryptedData) {
  const privateKeyBytes = Buffer.from(privateKey, 'base64');
  const encryptedMessage = Buffer.from(encryptedData, 'base64');
  const nonce = encryptedMessage.slice(0, nacl.box.nonceLength);
  const encryptedBytes = encryptedMessage.slice(nacl.box.nonceLength);
  const decryptedBytes = nacl.box.open(encryptedBytes, nonce, privateKeyBytes, nacl.box.keyPair().publicKey);
  
  if (decryptedBytes === null) {
    throw new Error('Decryption failed');
  }
  
  const decryptedData = Buffer.from(decryptedBytes).toString();
  return decryptedData;
}

const encryptedData = encryptWithPublicKey(keyPair.publicKey, data);
console.log('Encrypted Data:', encryptedData);

const decryptedData = decryptWithPrivateKey(keyPair.privateKey, encryptedData);
console.log('Decrypted Data:', decryptedData);


// encrypt(pub, data) -> edata
// decrypt(priv, eData) -> data
