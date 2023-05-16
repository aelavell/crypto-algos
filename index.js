const nacl = require('tweetnacl');
const { Buffer } = require('buffer');

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


