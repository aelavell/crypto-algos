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
console.log('verify data & signature' + verifyData(keyPair.publicKey, data, signature));



// encrypt(pub, data) -> edata
// decrypt(priv, eData) -> data
