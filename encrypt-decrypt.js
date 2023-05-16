const crypto = require('crypto');

// Function to generate a key pair
function generateKeyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
  });
  return {
    publicKey: publicKey.export({ format: 'pem', type: 'pkcs1' }),
    privateKey: privateKey.export({ format: 'pem', type: 'pkcs1' }),
  };
}

// Function to encrypt data with the public key
function encryptWithPublicKey(publicKey, data) {
  const buffer = Buffer.from(data);
  const encrypted = crypto.publicEncrypt(publicKey, buffer);
  return encrypted.toString('base64');
}

// Function to decrypt data with the private key
function decryptWithPrivateKey(privateKey, encryptedData) {
  const buffer = Buffer.from(encryptedData, 'base64');
  const decrypted = crypto.privateDecrypt(privateKey, buffer);
  return decrypted.toString();
}

// Example usage
const { publicKey, privateKey } = generateKeyPair();
console.log('Public Key:', publicKey);
console.log('Private Key:', privateKey);

const data = 'Koii Universe';
const encryptedData = encryptWithPublicKey(publicKey, data);
console.log('Encrypted Data:', encryptedData);

const decryptedData = decryptWithPrivateKey(privateKey, encryptedData);
console.log('Decrypted Data:', decryptedData);

