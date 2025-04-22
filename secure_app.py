import streamlit as st
import hashlib
from cryptography.fernet import Fernet

# --- Initialize session state for stored data, failed attempts, and encryption cipher ---
if "stored_data" not in st.session_state:
    st.session_state.stored_data = {}

if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

if "cipher" not in st.session_state:
    key = Fernet.generate_key()
    st.session_state.cipher = Fernet(key)

cipher = st.session_state.cipher


# --- Function to hash passkey using SHA256 ---
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()


# --- Function to encrypt text using Fernet ---
def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()


# --- Function to decrypt encrypted text ---
def decrypt_data(encrypted_text, passkey):
    hashed_passkey = hash_passkey(passkey)

    for data in st.session_state.stored_data.values():
        if (
            data["encrypted_text"] == encrypted_text
            and data["passkey"] == hashed_passkey
        ):
            st.session_state.failed_attempts = 0
            return cipher.decrypt(encrypted_text.encode()).decode()

    st.session_state.failed_attempts += 1
    return None


# --- Streamlit UI ---
st.title("🔒 Secure Data Encryption System")

menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Navigation", menu)

# --- Home Page ---
if choice == "Home":
    st.subheader("🏡 Welcome!")
    st.write("This app helps you store & retrieve encrypted data securely.")

# --- Store Data Page ---
elif choice == "Store Data":
    st.subheader("📂 Store Your Secret Data")
    user_data = st.text_area("Enter the data you want to store:")
    passkey = st.text_input("Enter a secret passkey:")

    if st.button("Encrypt & Store"):
        if user_data and passkey:
            encrypted = encrypt_data(user_data)
            hashed = hash_passkey(passkey)
            st.session_state.stored_data[encrypted] = {
                "encrypted_text": encrypted,
                "passkey": hashed,
            }
            st.success("✅ Your data is now encrypted and stored!")
            st.code(encrypted, language="text")
        else:
            st.warning("⚠ Please fill both fields.")

# --- Retrieve Data Page ---
elif choice == "Retrieve Data":
    st.subheader("🔍 Retrieve Encrypted Data")
    encrypted_text = st.text_area("Paste the encrypted text:")
    passkey = st.text_input("Enter your passkey:", type="password")

    if st.button("Decrypt"):
        if encrypted_text and passkey:
            result = decrypt_data(encrypted_text, passkey)
            if result:
                st.success(f"✅ Decrypted Text: {result}")
            else:
                remaining = 3 - st.session_state.failed_attempts
                st.error(f"❌ Wrong passkey! Remaining attempts: {remaining}")
                if st.session_state.failed_attempts >= 3:
                    st.warning("🔒 Too many wrong attempts. Please login again.")
                    st.experimental_rerun()
        else:
            st.warning("⚠ Please enter both fields.")

# --- Login Page (used after 3 failed attempts) ---
elif choice == "Login":
    st.subheader("🔑 Login")
    master_pass = st.text_input("Enter master password:", type="password")

    if st.button("Login"):
        if master_pass == "admin123":
            st.session_state.failed_attempts = 0
            st.success("✅ Access restored!")
            st.experimental_rerun()
        else:
            st.error("❌ Wrong master password.")
