import streamlit as st
import os
import requests
from umbral import SecretKey, Signer, pre, Capsule, VerifiedCapsuleFrag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

API_BASE_URL = "http://127.0.0.1:8000"
FILE_ID = "demo_file_001"
RECIPIENT_ID = "vansh_tyagi_node"

st.set_page_config(page_title="Zero-Trust File Share", layout="centered")
st.title("Zero-Trust PRE File Sharing")

# --- DISK-BASED KEY MANAGEMENT ---
# This ensures all devices see the same keys for the MVP demonstration
def get_or_create_key(filename):
    if os.path.exists(filename):
        with open(filename, "rb") as f:
            return SecretKey.from_bytes(f.read())
    else:
        new_key = SecretKey.random()
        with open(filename, "wb") as f:
            f.write(new_key.to_secret_bytes())
        return new_key

owner_priv = get_or_create_key("owner_priv.key")
recip_priv = get_or_create_key("recip_priv.key")

tab1, tab2 = st.tabs(["Upload & Share (Data Owner)", "Download & Decrypt (Recipient)"])

# --- TAB 1: SENDER ---
with tab1:
    st.header("1. Encrypt and Delegate Access")
    uploaded_file = st.file_uploader("Select a file to securely share")
    
    if st.button("Encrypt & Send to Proxy") and uploaded_file is not None:
        with st.spinner("Encrypting with AES-256-GCM..."):
            file_bytes = uploaded_file.read()
            aes_key = AESGCM.generate_key(bit_length=256)
            nonce = os.urandom(12)
            aesgcm = AESGCM(aes_key)
            ciphertext_file = aesgcm.encrypt(nonce, file_bytes, None)
            
            with open("encrypted_storage.enc", "wb") as f:
                f.write(nonce + ciphertext_file)

        with st.spinner("Encapsulating AES key via pyUmbral..."):
            owner_pub = owner_priv.public_key()
            recip_pub = recip_priv.public_key()
            
            capsule, key_ciphertext = pre.encrypt(owner_pub, aes_key)
            
            # Save capsule and ciphertext to disk instead of session state
            with open("capsule.bin", "wb") as f:
                f.write(bytes(capsule))
            with open("key_ciphertext.bin", "wb") as f:
                f.write(key_ciphertext)
            
            kfrags = pre.generate_kfrags(
                delegating_sk=owner_priv,
                receiving_pk=recip_pub,
                signer=Signer(owner_priv),
                threshold=1,
                shares=1
            )
            
            requests.post(f"{API_BASE_URL}/upload_capsule", json={
                "file_id": FILE_ID, "capsule_bytes": bytes(capsule).hex()
            })
            requests.post(f"{API_BASE_URL}/grant_access", json={
                "file_id": FILE_ID, "recipient_id": RECIPIENT_ID, "kfrag_bytes": bytes(kfrags[0]).hex()
            })
            st.success("Cryptographic Capsule and KFrag sent to Zero-Trust Proxy!")

# --- TAB 2: RECIPIENT ---
with tab2:
    st.header("2. Request Access and Decrypt")
    
    if st.button("Fetch & Decrypt File"):
        with st.spinner("Requesting Re-encryption from Proxy..."):
            res = requests.get(f"{API_BASE_URL}/reencrypt/{FILE_ID}/{RECIPIENT_ID}")
            
            if res.status_code == 200:
                cfrag_hex = res.json()["cfrag_bytes"]
                cfrag = VerifiedCapsuleFrag.from_verified_bytes(bytes.fromhex(cfrag_hex))
                
                # Load the exact same capsule and ciphertext from disk
                with open("capsule.bin", "rb") as f:
                    capsule = Capsule.from_bytes(f.read())
                with open("key_ciphertext.bin", "rb") as f:
                    key_ciphertext = f.read()
                
                with st.spinner("Decrypting AES master key..."):
                    recovered_aes_key = pre.decrypt_reencrypted(
                        receiving_sk=recip_priv,
                        delegating_pk=owner_priv.public_key(),
                        capsule=capsule,
                        verified_cfrags=[cfrag],
                        ciphertext=key_ciphertext
                    )
                
                with st.spinner("Decrypting original file..."):
                    with open("encrypted_storage.enc", "rb") as f:
                        enc_data = f.read()
                    
                    rec_nonce, rec_ciphertext = enc_data[:12], enc_data[12:]
                    recipient_aes = AESGCM(recovered_aes_key)
                    decrypted_file = recipient_aes.decrypt(rec_nonce, rec_ciphertext, None)
                    
                    st.success("File successfully decrypted!")
                    st.download_button(
                        label="Download Decrypted File",
                        data=decrypted_file,
                        file_name="recovered_file.jpg",
                    )
            else:
                st.error(f"Proxy denied request or failed: {res.text}")
