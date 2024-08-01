const { Buffer } = require('buffer');
const { keccak256 } = require('ethereumjs-util');
const elliptic = require('elliptic');
const crypto = require('crypto');
const fs = require('fs');

// Initialize elliptic curve (secp256k1)
const ec = new elliptic.ec('secp256k1');

// Helper function to generate a random key pair
function generateKeyPair() {
    const key = ec.genKeyPair();
    return {
        privateKey: key.getPrivate(),
        publicKey: key.getPublic(),
    };
}

// Hashing function
function hashPoint(point) {
    // Convert point to a buffer
    const pointBuffer = Buffer.from(point.encode('array'));
    // Hash the buffer using keccak256
    return Buffer.from(keccak256(pointBuffer));
}

// Generate a stealth address
function generateStealthAddress(senderPrivateKey, recipientPublicKeyHex) {
    // Generate ephemeral key pair for sender
    const ephemeralKeyPair = generateKeyPair();
    const ephemeralPrivateKey = ephemeralKeyPair.privateKey;
    const ephemeralPublicKey = ephemeralKeyPair.publicKey;

    // Convert recipient's public key to elliptic curve point
    const recipientPoint = ec.keyFromPublic(recipientPublicKeyHex, 'hex').getPublic();
    const ephemeralPoint = ec.keyFromPrivate(ephemeralPrivateKey).getPublic();

    // Compute shared secret k = p * R
    const sharedSecretPoint = recipientPoint.mul(ephemeralPrivateKey);

    // Hash the shared secret point
    const hashedSecret = hashPoint(sharedSecretPoint);

    // Derive Kh = kh * G
    const generatorPoint = ec.genKeyPair().getPublic(); // G is the generator point
    const Kh = ec.keyFromPrivate(hashedSecret).getPublic();

    // Generate stealth address Rst = Kh + R
    const stealthAddress = Kh.add(recipientPoint);

    return {
        stealthAddress: stealthAddress.encode('hex'), // Encode the stealth address as hex
        ephemeralPublicKey: ephemeralPublicKey.encode('hex') // Encode the ephemeral public key as hex
    };
}

// Example usage
const recipientPrivateKeyHex = '0x123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
const recipientPublicKeyHex = ec.keyFromPrivate(Buffer.from(recipientPrivateKeyHex.slice(2), 'hex')).getPublic('hex'); // Convert private key to public key hex

const senderPrivateKey = crypto.randomBytes(32); // Generate a random private key for the sender
const senderPublicKey = ec.keyFromPrivate(senderPrivateKey).getPublic();

const { stealthAddress, ephemeralPublicKey } = generateStealthAddress(senderPrivateKey, recipientPublicKeyHex);

console.log('Stealth Address:', stealthAddress);
console.log('Ephemeral Public Key:', ephemeralPublicKey);

// Save ephemeral public key to a file
fs.writeFileSync('ephemeralPublicKeys.txt', ephemeralPublicKey + '\n', { flag: 'a' });



// In this setup:

// generator.js generates a stealth address and an ephemeral public key, then saves the ephemeral public key to a file ephemeralPublicKeys.txt.
// parsing.js reads the ephemeral public keys from ephemeralPublicKeys.txt and processes each key to derive the corresponding Ethereum address and private key.
// To run this, execute generator.js multiple times to generate and store multiple ephemeral public keys. Then run parsing.js to parse those keys.


--------


const { Buffer } = require('buffer');
const { keccak256 } = require('ethereumjs-util');
const elliptic = require('elliptic');
const fs = require('fs');

// Initialize elliptic curve (secp256k1)
const ec = new elliptic.ec('secp256k1');

// Function to hash a point using keccak256
function hashPoint(point) {
    // Convert point to a buffer
    const pointBuffer = Buffer.from(point.encode('array'));
    // Hash the buffer using keccak256
    return Buffer.from(keccak256(pointBuffer));
}

// Function to parse the stealth address
function parseStealthAddress(ephemeralPublicKeys, recipientPrivateKeyHex) {
    const recipientPrivateKey = ec.keyFromPrivate(recipientPrivateKeyHex.slice(2), 'hex'); // Remove '0x' prefix
    const recipientPrivateKeyBn = recipientPrivateKey.getPrivate();

    // Iterate through each ephemeral public key
    for (let i = 0; i < ephemeralPublicKeys.length; i++) {
        let ephemeralPublicKeyHex = ephemeralPublicKeys[i].trim();

        // Ensure the public key is in the correct format (uncompressed, 130 characters)
        if (ephemeralPublicKeyHex.length === 128) {
            // Add the missing '04' prefix for uncompressed public key
            ephemeralPublicKeyHex = '04' + ephemeralPublicKeyHex;
        } else if (ephemeralPublicKeyHex.length !== 130 || !ephemeralPublicKeyHex.startsWith('04')) {
            console.error('Invalid ephemeral public key format:', ephemeralPublicKeyHex);
            continue;
        }

        const ephemeralPublicKey = ec.keyFromPublic(ephemeralPublicKeyHex, 'hex').getPublic();

        // Step 1: Multiply P with the private key r : k=r×P
        const sharedSecretPoint = ephemeralPublicKey.mul(recipientPrivateKeyBn);

        // Step 2: Hash the derived shared secret kh=h(k)
        const hashedSecret = hashPoint(sharedSecretPoint);

        // Step 3: Add the result of (2) to the own private key: rst=kh+r
        const hashedSecretBn = ec.keyFromPrivate(hashedSecret).getPrivate();
        const stealthPrivateKey = recipientPrivateKeyBn.add(hashedSecretBn).umod(ec.curve.n);

        // Step 4: Multiply the result of (3) with the generator point to derive the stealth public key: Rst=rst×G
        const stealthPublicKey = ec.g.mul(stealthPrivateKey);

        // Step 5: Hash the stealth public key and take the least significant 20 bytes to derive the Ethereum address: Raddrst=h(Rst)[−20:]
        const stealthPublicKeyHash = Buffer.from(keccak256(Buffer.from(stealthPublicKey.encode('array'))));
        const ethereumAddress = stealthPublicKeyHash.slice(-20).toString('hex');

        // Check if the derived Ethereum address has been the recipient of the transaction
        // This step requires additional logic to check the blockchain for transactions
        // involving the derived Ethereum address (Raddrst).
        // Here we simply print the derived address for demonstration purposes.
        console.log('Derived Ethereum Address:', ethereumAddress);

        // If the check is successful, the recipient may store the private key rst.
        // This is just a demonstration of storing the private key.
        // In practice, you would securely store this key.
        console.log('Corresponding Private Key:', stealthPrivateKey.toString(16));

        
    }
}

// Example usage
const recipientPrivateKeyHex = '0x123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';

// Read ephemeral public keys from the file
const ephemeralPublicKeys = fs.readFileSync('ephemeralPublicKeys.txt', 'utf-8').split('\n').filter(Boolean);

parseStealthAddress(ephemeralPublicKeys, recipientPrivateKeyHex);



