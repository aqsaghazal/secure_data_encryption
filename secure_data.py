import streamlit as st
import hashlib
import json
import time
from datetime import datetime, timedelta
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Constants
MAX_ATTEMPTS = 3
LOCKOUT_DURATION = 300  # 5 minutes in seconds
DATA_FILE = "encrypted_data.json"

# Initialize session state
if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0
if 'last_attempt_time' not in st.session_state:
    st.session_state.last_attempt_time = None
if 'is_locked' not in st.session_state:
    st.session_state.is_locked = False
if 'is_authenticated' not in st.session_state:
    st.session_state.is_authenticated = False

# Generate or load encryption key
def get_encryption_key():
    key = os.getenv('ENCRYPTION_KEY')
    if not key:
        key = Fernet.generate_key()
        with open('.env', 'a') as f:
            f.write(f'\nENCRYPTION_KEY={key.decode()}')
    return key

# Initialize Fernet cipher
cipher = Fernet(get_encryption_key())

# Load stored data
def load_data():
    try:
        with open(DATA_FILE, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}

# Save data
def save_data(data):
    with open(DATA_FILE, 'w') as f:
        json.dump(data, f)

# Enhanced password hashing using PBKDF2
def hash_passkey(passkey, salt=None):
    if not salt:
        salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(passkey.encode()))
    return key, salt

# Encrypt data
def encrypt_data(text, passkey):
    salt = os.urandom(16)
    key, salt = hash_passkey(passkey, salt)
    cipher = Fernet(key)
    encrypted_text = cipher.encrypt(text.encode())
    return encrypted_text.decode(), salt.hex()

# Decrypt data
def decrypt_data(encrypted_text, passkey, salt_hex):
    try:
        salt = bytes.fromhex(salt_hex)
        key, _ = hash_passkey(passkey, salt)
        cipher = Fernet(key)
        return cipher.decrypt(encrypted_text.encode()).decode()
    except:
        return None

# Check if user is locked out
def check_lockout():
    if st.session_state.is_locked:
        if st.session_state.last_attempt_time:
            elapsed = time.time() - st.session_state.last_attempt_time
            if elapsed >= LOCKOUT_DURATION:
                st.session_state.is_locked = False
                st.session_state.failed_attempts = 0
                return False
        return True
    return False

# Custom CSS for better UI
st.markdown("""
    <style>
    .main {
        background-color: #f5f5f5;
    }
    .stButton>button {
        background-color: #4CAF50;
        color: white;
        border-radius: 5px;
        padding: 0.5rem 1rem;
        border: none;
    }
    .stTextInput>div>div>input {
        border-radius: 5px;
    }
    .stTextArea>div>div>textarea {
        border-radius: 5px;
    }
    </style>
""", unsafe_allow_html=True)

# Main app
st.title("🔒 Secure Data Encryption System")
st.markdown("---")

# Navigation
menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Navigation", menu)

if choice == "Home":
    st.subheader("🏠 Welcome to the Secure Data System")
    st.write("""
    This application allows you to securely store and retrieve sensitive data using strong encryption.
    
    ### Features:
    - 🔐 Strong encryption using Fernet
    - 🔑 Secure passkey hashing with PBKDF2
    - ⏱️ Automatic lockout after multiple failed attempts
    - 💾 Persistent data storage
    - 🎨 Modern and user-friendly interface
    
    ### How to use:
    1. Navigate to 'Store Data' to encrypt and save your information
    2. Use 'Retrieve Data' to access your stored data
    3. If you exceed the maximum attempts, you'll need to reauthenticate
    """)

elif choice == "Store Data":
    st.subheader("📂 Store Data Securely")
    user_data = st.text_area("Enter Data to Encrypt:", height=150)
    passkey = st.text_input("Enter Passkey:", type="password")
    confirm_passkey = st.text_input("Confirm Passkey:", type="password")

    if st.button("Encrypt & Save"):
        if user_data and passkey and confirm_passkey:
            if passkey != confirm_passkey:
                st.error("⚠️ Passkeys do not match!")
            else:
                stored_data = load_data()
                encrypted_text, salt = encrypt_data(user_data, passkey)
                stored_data[encrypted_text] = {
                    "encrypted_text": encrypted_text,
                    "salt": salt
                }
                save_data(stored_data)
                st.success("✅ Data stored securely!")
                st.info("🔑 Please save your encrypted data and passkey safely!")
                st.code(encrypted_text)
        else:
            st.error("⚠️ All fields are required!")

elif choice == "Retrieve Data":
    st.subheader("🔍 Retrieve Your Data")
    
    if check_lockout():
        st.error(f"🔒 Account locked! Please try again in {int((LOCKOUT_DURATION - (time.time() - st.session_state.last_attempt_time)) / 60)} minutes.")
        st.button("Go to Login", on_click=lambda: st.experimental_rerun())
    else:
        encrypted_text = st.text_area("Enter Encrypted Data:", height=150)
        passkey = st.text_input("Enter Passkey:", type="password")

        if st.button("Decrypt"):
            if encrypted_text and passkey:
                stored_data = load_data()
                if encrypted_text in stored_data:
                    salt_hex = stored_data[encrypted_text]["salt"]
                    decrypted_text = decrypt_data(encrypted_text, passkey, salt_hex)
                    
                    if decrypted_text:
                        st.session_state.failed_attempts = 0
                        st.success("✅ Data decrypted successfully!")
                        st.text_area("Decrypted Data:", decrypted_text, height=150)
                    else:
                        st.session_state.failed_attempts += 1
                        st.error(f"❌ Incorrect passkey! Attempts remaining: {MAX_ATTEMPTS - st.session_state.failed_attempts}")
                        
                        if st.session_state.failed_attempts >= MAX_ATTEMPTS:
                            st.session_state.is_locked = True
                            st.session_state.last_attempt_time = time.time()
                            st.warning("🔒 Too many failed attempts! Please login to continue.")
                            st.button("Go to Login", on_click=lambda: st.experimental_rerun())
                else:
                    st.error("❌ Encrypted data not found!")
            else:
                st.error("⚠️ Both fields are required!")

elif choice == "Login":
    st.subheader("🔑 Reauthorization Required")
    login_pass = st.text_input("Enter Master Password:", type="password")

    if st.button("Login"):
        # In a real application, use proper authentication
        if login_pass == "admin123":  # Replace with proper auth
            st.session_state.is_authenticated = True
            st.session_state.failed_attempts = 0
            st.session_state.is_locked = False
            st.success("✅ Reauthorized successfully!")
            st.button("Continue to Retrieve Data", on_click=lambda: st.experimental_rerun())
        else:
            st.error("❌ Incorrect password!") 