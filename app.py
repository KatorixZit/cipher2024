import streamlit as st
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP, AES
from Cryptodome.Random import get_random_bytes
from Cryptodome.Util.Padding import pad, unpad
from Cryptodome.Hash import SHA256
from Cryptodome.Signature import pss

import base64


# Function to encrypt messages using the provided public key (RSA)
def encrypt_message_rsa(public_key, message):
    try:
        key_size = public_key.size_in_bytes()
        max_chunk_size = key_size - 42
        chunks = [
            message[i : i + max_chunk_size]
            for i in range(0, len(message), max_chunk_size)
        ]
        encrypted_chunks = []
        cipher = PKCS1_OAEP.new(public_key)
        for chunk in chunks:
            encrypted_chunk = cipher.encrypt(chunk.encode())
            encrypted_chunks.append(base64.b64encode(encrypted_chunk).decode())
        delimiter = "|"
        encrypted_message = delimiter.join(encrypted_chunks)
        return True, encrypted_message
    except Exception as e:
        return False, str(e)


# Function to decrypt messages using the provided private key (RSA)
def decrypt_message_rsa(private_key, encrypted_message):
    try:
        cipher = PKCS1_OAEP.new(private_key)
        encrypted_chunks = encrypted_message.split("|")
        decrypted_chunks = []
        for chunk in encrypted_chunks:
            decrypted_chunk = cipher.decrypt(base64.b64decode(chunk))
            decrypted_chunks.append(decrypted_chunk)
        decrypted_message = b"".join(decrypted_chunks)
        return True, decrypted_message.decode()
    except Exception as e:
        return False, str(e)


# Function to generate RSA keys
def generate_rsa_keys(key_size=2048):
    try:
        key = RSA.generate(key_size)
        private_key = key.export_key()
        public_key = key.publickey().export_key()
        return True, private_key, public_key
    except Exception as e:
        return False, str(e), None


# Helper function for message input
def get_message_from_user(input_type, file_uploader_key, text_area_key):
    if input_type == "Type":
        message = st.text_area("Type your message here:", key=text_area_key)
        return message.encode("utf-8") if message else None
    elif input_type == "Upload":
        uploaded_file = st.file_uploader(
            "Or upload a .txt file:", type=["txt"], key=file_uploader_key
        )
        if uploaded_file is not None:
            return uploaded_file.getvalue()
    return None



def generate_signature(message: bytes, private_key):
    try:
        message_hash = SHA256.new(message)
        signSystem = pss.new(private_key)

        signature = signSystem.sign(message_hash)
        return True, base64.b64encode(signature).decode('utf-8')
    except Exception as e:
        return False, str(e)


def verify_signature(message: bytes, public_key, signature:bytes):
    message_hash = SHA256.new(message)
    verifySystem = pss.new(public_key)

    try:
        verifySystem.verify(message_hash, base64.b64decode(signature.decode("utf-8")))
        return True, "Verify Success!"
    except:
        return False, "Not verified"
    

# Streamlit UI
st.sidebar.title("Navigation")
app_mode = st.sidebar.selectbox(
    "Choose the app mode",
    [
        "Home",
        "Generate RSA Keys",
        "RSA Encrypt Message",
        "RSA Decrypt Message",
        "RSA Digital Sign",
        "RSA Digital Verify"
    ],
)

if app_mode == "Home":
    st.title("RSA Encryption/Decryption App")
    st.write(
        "Welcome to the RSA Encryption/Decryption App. Please select an option from the navigation bar to start."
    )

elif app_mode == "Generate RSA Keys":
    st.title("Generate RSA Keys")
    key_size_option = st.selectbox("Select Key Size", [256, 512, 1024, 2048, 3072, 4096, 8192, 16384, 32768], index=0)
    if st.button("Generate Keys"):
        with st.spinner("Generating RSA Keys..."):
            success, private_key, public_key = generate_rsa_keys(
                key_size=key_size_option
            )
        if success:
            st.success("Keys generated successfully!")
            st.text_area("Public Key", public_key.decode("utf-8"), height=250)
            st.download_button(
                "Download Public Key", public_key, "public_key.pem", "text/plain"
            )
            st.text_area("Private Key", private_key.decode("utf-8"), height=250)
            st.download_button(
                "Download Private Key", private_key, "private_key.pem", "text/plain"
            )
            st.warning(
                "Remember to store your private key in a secure location. It is crucial for decrypting your messages and must be kept confidential."
            )
        else:
            st.error("Failed to generate keys.")

elif app_mode in ["RSA Encrypt Message", "RSA Decrypt Message"]:
    pub_key = (
        st.file_uploader("Upload RSA Public Key", type=["pem"])
        if app_mode == "RSA Encrypt Message"
        else None
    )
    priv_key = (
        st.file_uploader("Upload RSA Private Key", type=["pem"])
        if app_mode == "RSA Decrypt Message"
        else None
    )
    input_type = st.radio("Message input method:", ("Type", "Upload"), index=0)
    message = get_message_from_user(input_type, "file_uploader", "text_area")

    if message:
        if app_mode == "RSA Encrypt Message" and pub_key:
            public_key = RSA.import_key(pub_key.getvalue())
            success, result = encrypt_message_rsa(public_key, message.decode("utf-8"))
        elif app_mode == "RSA Decrypt Message" and priv_key:
            private_key = RSA.import_key(priv_key.getvalue())
            success, result = decrypt_message_rsa(private_key, message.decode("utf-8"))
        else:
            success, result = False, "Required key not provided."

        if success:
            st.text_area("Result", result, height=100)
            st.download_button("Download Result", result, "result.txt", "text/plain")
        else:
            st.error(f"Operation failed: {result}")

elif app_mode in ["RSA Digital Sign", "RSA Digital Verify"]:
    pub_key = (
        st.file_uploader("Upload RSA Public Key", type=["pem"])
        if app_mode == "RSA Digital Verify"
        else None
    )
    priv_key = (
        st.file_uploader("Upload RSA Private Key", type=["pem"])
        if app_mode == "RSA Digital Sign"
        else None
    )
    signature = (
        st.file_uploader("Upload RSA Signature", type=["txt"])
        if app_mode == "RSA Digital Verify"
        else None
    )

    input_type = st.radio("Message input method:", ("Type", "Upload"), index=0)
    message = get_message_from_user(input_type, "file_uploader", "text_area")

    if message:
        if app_mode == "RSA Digital Sign" and priv_key:
            private_key = RSA.import_key(priv_key.getvalue())
            success, result = generate_signature(message=message, private_key=private_key)
        elif app_mode == "RSA Digital Verify" and pub_key and signature:
            pubic_key = RSA.import_key(pub_key.getvalue())
            success, result = verify_signature(message=message, public_key=pubic_key, signature=signature.getvalue())
        else:
            success, result = False, "Required key or signature not provided."

        if success:
            st.text_area("Result", result, height=100)
            st.download_button("Download Result", result, "result.txt", "text/plain")
        else:
            st.error(f"{result}")