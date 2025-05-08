const { encrypt, decrypt } = require('../utils/crypto');

describe('Crypto Utility Functions', () => {
  const plaintext = 'Hello, this is a secret message!';

  test('should encrypt and decrypt correctly', () => {
    const encrypted = encrypt(plaintext);
    const decrypted = decrypt(encrypted);
    expect(decrypted).toBe(plaintext);
  });

  test('should produce different encrypted outputs for the same input', () => {
    const encrypted1 = encrypt(plaintext);
    const encrypted2 = encrypt(plaintext);
    expect(encrypted1).not.toBe(encrypted2);
  });

  test('should fail gracefully with invalid ciphertext format', () => {
    const brokenCipherText = 'invalid:message:data';
    const decrypted = decrypt(brokenCipherText);
    expect(decrypted).toMatch(/error/i);
  });

  test('should return a string even on decryption failure', () => {
    const brokenCipherText = 'invalid:data';
    const decrypted = decrypt(brokenCipherText);
    expect(typeof decrypted).toBe('string');
  });

  test('should return a string from successful decrypt', () => {
    const encrypted = encrypt(plaintext);
    const decrypted = decrypt(encrypted);
    expect(typeof decrypted).toBe('string');
    expect(decrypted).toBe(plaintext);
  });
});
