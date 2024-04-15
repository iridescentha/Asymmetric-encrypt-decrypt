document.addEventListener('DOMContentLoaded', function(){
  const generateBtn = document.querySelector('.generateBtn');
  const bitLength = document.querySelector('.keyLength');
  const publicKeyTextarea = document.querySelector('.publicKeyTextarea');
  const privateKeyTextarea = document.querySelector('.privateKeyTextarea');
  const encryptBtn = document.querySelector('.encryptBtn');
  const decryptBtn = document.querySelector('.decryptBtn');
  const encryptedOutput = document.querySelector('.encryptedResult');
  const decryptedOutput = document.querySelector('.decryptedResult');
  let publicKey;

  async function generateKeyPair(bitLength) {
    return await window.crypto.subtle.generateKey(
      {
        name: "RSA-OAEP",
        modulusLength: bitLength,
        publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
        hash: "SHA-256"
      },
      true,
      ["encrypt", "decrypt"]
    );
  }
  
  async function encrypt(publicKey, plaintext) {
    const encodedText = new TextEncoder().encode(plaintext);
    return await window.crypto.subtle.encrypt(
      {
       name: "RSA-OAEP"
      },
      publicKey,
      encodedText
    );
  }
  
  async function decrypt(privateKey, ciphertext) {
    const decrypted = await window.crypto.subtle.decrypt(
      {
        name: "RSA-OAEP"
      },
      privateKey,
      ciphertext
    );
    return new TextDecoder().decode(decrypted);
  }
  
  async function main() { 
    generateBtn.addEventListener('click', async function(){
      const keyPair = await generateKeyPair(bitLength.value);
      publicKey = keyPair.publicKey;
      const privateKey = keyPair.privateKey;
      const publicKeyString = await exportKeyAsString(publicKey);
      const privateKeyString = await exportKeyAsString(privateKey);
      console.log(publicKey);
      console.log(privateKey);
      publicKeyTextarea.value = publicKeyString;
      privateKeyTextarea.value = privateKeyString;
    })
    encryptBtn.addEventListener('click', async function(){
      const plainText = document.querySelector('.plainTextInput').value;
      const publicKeytext = document.querySelector('.publicKeyInput').value;
      if (plainText == '' || publicKeytext == ''){
        window.alert('Please enter both fields to encrypt');
      } else {
        try {
          const publicKey = await importPublicKey(publicKeytext);
          const encryptedText = await encrypt(publicKey, plainText);
          const encryptedArray = new Uint8Array(encryptedText);
          console.log(encryptedArray);
          const encryptedBase64 = btoa(String.fromCharCode.apply(null, encryptedArray));
          encryptedOutput.value = encryptedBase64;
        } catch (error) {
          consoele.error("Encryption error:", error);
        }
      }
    });
    decryptBtn.addEventListener('click', async function(){
      const cipherTextBase64 = document.querySelector('.cipherTextInput').value;
      const privateKeyText = document.querySelector('.privateKeyInput').value;
      if (cipherTextBase64 == '' || privateKeyText == ''){
          window.alert('Please enter both fields to decrypt');
      } else {
          try {
              const privateKey = await importPrivateKey(privateKeyText);              
              const ciphertextArrayBuffer = base64ToArrayBuffer(cipherTextBase64);
              const decryptedText = await decrypt(privateKey, ciphertextArrayBuffer);
              decryptedOutput.value = decryptedText;
          } catch (error) {
              console.error("Decryption error:", error);
          }
      }
  });
}

function base64ToArrayBuffer(base64) {
  const binary_string = atob(base64);
  const len = binary_string.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
      bytes[i] = binary_string.charCodeAt(i);
  }
  return bytes.buffer;
}
  
  async function exportKeyAsString(key) {
    try {
        const exportedKey = await window.crypto.subtle.exportKey(
            "jwk",
            key
        );
        return JSON.stringify(exportedKey);
    } catch (error) {
        console.error("Error exporting key:", error);
        throw error;
    }
  }
  async function importPublicKey(publicKeyString) {
    try {
      const publicKeyObject = JSON.parse(publicKeyString);
      
      return await window.crypto.subtle.importKey(
        "jwk",
        publicKeyObject,
        { name: "RSA-OAEP", hash: "SHA-256" },
        true,
        ["encrypt"]
      );
    } catch (error) {
      console.error("Error importing public key:", error);
      throw error;
    }
  }
  
  async function importPrivateKey(privateKeyString) {
    try {
        const privateKeyObject = JSON.parse(privateKeyString);

        return await window.crypto.subtle.importKey(
            "jwk",
            privateKeyObject,
            { name: "RSA-OAEP", hash: "SHA-256" },
            true,
            ["decrypt"]
        );
    } catch (error) {
        console.error("Error importing private key:", error);
        throw error;
    }
}

  main();
})
