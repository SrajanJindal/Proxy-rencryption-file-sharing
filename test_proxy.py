import os
import requests
from umbral import SecretKey, Signer, pre, VerifiedCapsuleFrag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

API_BASE_URL = "http://127.0.0.1:8000" 
FILE_ID = "test_file_001"
RECIPIENT_ID = "vansh_tyagi_node"

def run_hybrid_test():
    # --- 0. SETUP DUMMY FILE ---
    print("0. Creating a dummy test file...")
    dummy_file_data = b"This is a highly classified document for the major project."
    with open("test_document.pdf", "wb") as f:
        f.write(dummy_file_data)
        
    print("\n--- 1. OWNER: ENCRYPTING FILE WITH AES ---")
    # Generate a 256-bit AES key and a random 12-byte nonce
    aes_key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    
    # Read the file and encrypt it
    aesgcm = AESGCM(aes_key)
    with open("test_document.pdf", "rb") as f:
        file_bytes = f.read()
        
    encrypted_file_bytes = aesgcm.encrypt(nonce, file_bytes, None)
    
    # Prepend the nonce to the ciphertext for storage/sharing
    with open("test_document.pdf.enc", "wb") as f:
        f.write(nonce + encrypted_file_bytes)
    print("File successfully encrypted locally as 'test_document.pdf.enc'")

    print("\n--- 2. OWNER: ENCAPSULATING AES KEY WITH UMBRAL ---")
    owner_private = SecretKey.random()
    owner_public = owner_private.public_key()
    owner_signer = Signer(owner_private)

    recipient_private = SecretKey.random()
    recipient_public = recipient_private.public_key()

    # The AES key becomes the plaintext that Umbral encrypts!
    capsule, key_ciphertext = pre.encrypt(owner_public, aes_key)

    kfrags = pre.generate_kfrags(
        delegating_sk=owner_private,
        receiving_pk=recipient_public,
        signer=owner_signer,
        threshold=1,
        shares=1
    )
    kfrag = kfrags[0]

    print("\n--- 3. SENDING DATA TO RASPBERRY PI PROXY ---")
    res1 = requests.post(f"{API_BASE_URL}/upload_capsule", json={
        "file_id": FILE_ID,
        "capsule_bytes": bytes(capsule).hex()
    })
    print("Upload Capsule Response:", res1.json())

    res2 = requests.post(f"{API_BASE_URL}/grant_access", json={
        "file_id": FILE_ID,
        "recipient_id": RECIPIENT_ID,
        "kfrag_bytes": bytes(kfrag).hex()
    })
    print("Grant Access Response:", res2.json())

    print("\n--- 4. RECIPIENT: REQUESTING RE-ENCRYPTION ---")
    res3 = requests.get(f"{API_BASE_URL}/reencrypt/{FILE_ID}/{RECIPIENT_ID}")
    
    if res3.status_code == 200:
        cfrag_hex = res3.json()["cfrag_bytes"]
        print("Success! Proxy returned CFrag.")

        print("\n--- 5. RECIPIENT: DECRYPTING HYBRID PAYLOAD ---")
        cfrag = VerifiedCapsuleFrag.from_verified_bytes(bytes.fromhex(cfrag_hex))

        # First, decrypt the AES key using Umbral
        decrypted_aes_key = pre.decrypt_reencrypted(
            receiving_sk=recipient_private,
            delegating_pk=owner_public,
            capsule=capsule,
            verified_cfrags=[cfrag],
            ciphertext=key_ciphertext
        )
        print("Successfully recovered the AES master key from the Umbral capsule!")
        assert decrypted_aes_key == aes_key, "Key mismatch!"

        # Second, decrypt the actual file using the recovered AES key
        with open("test_document.pdf.enc", "rb") as f:
            stored_data = f.read()
            
        # Extract the 12-byte nonce from the beginning of the file
        rec_nonce = stored_data[:12]
        rec_ciphertext = stored_data[12:]
        
        recipient_aesgcm = AESGCM(decrypted_aes_key)
        decrypted_file_bytes = recipient_aesgcm.decrypt(rec_nonce, rec_ciphertext, None)
        
        with open("recovered_document.pdf", "wb") as f:
            f.write(decrypted_file_bytes)
            
        print("Successfully decrypted the file using the recovered AES key!")
        assert decrypted_file_bytes == dummy_file_data, "File data corrupted!"
        print("\nVerification Complete: Full Hybrid Architecture is 100% functional!")
        
    else:
        print("Failed to re-encrypt:", res3.text)

if __name__ == "__main__":
    run_hybrid_test()
