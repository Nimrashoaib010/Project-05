import streamlit as st
import hashlib
import json
import os
from cryptography.fernet import Fernet

# Initialize encryption key and cipher
KEY = Fernet.generate_key()
cipher = Fernet(KEY)

# Save the key permanently in a file
KEY_FILE = "secret.key"

def load_key():
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as file:
            return file.read()
    else:
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as file:
            file.write(key)
        return key

KEY = load_key()
cipher = Fernet(KEY)


# File paths
USER_FILE = "users.json"
DATA_FILE = "data.json"

# Load user credentials
def load_users():
    if os.path.exists(USER_FILE):
        with open(USER_FILE, "r") as file:
            return json.load(file)
    return {}

def save_users(users):
    with open(USER_FILE, "w") as file:
        json.dump(users, file)

def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as file:
            return json.load(file)
    return {}

def save_data(data):
    with open(DATA_FILE, "w") as file:
        json.dump(data, file)

# Initial load
users = load_users()
stored_data = load_data()

# Session state initialization
if "current_user" not in st.session_state:
    st.session_state.current_user = None
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

# Utility Functions
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text):
    return cipher.decrypt(encrypted_text.encode()).decode()

def authenticate_user(username, password):
    return username in users and users[username] == hash_passkey(password)

# Streamlit Pages
def signup():
    st.subheader("📝 Signup Page")
    new_username = st.text_input("Choose Username")
    new_password = st.text_input("Choose Password", type="password")

    if st.button("Signup"):
        if new_username and new_password:
            if new_username in users:
                st.error("🚫 Username already exists!")
            else:
                users[new_username] = hash_passkey(new_password)
                save_users(users)
                st.success("✅ Account created successfully! Please login.")
        else:
            st.warning("⚠️ Both fields are required.")

def login():
    st.subheader("🔐 Login Page")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        if authenticate_user(username, password):
            st.session_state.current_user = username
            st.session_state.failed_attempts = 0
            st.success(f"✅ Welcome, {username}!")
        else:
            st.session_state.failed_attempts += 1
            st.error(f"❌ Incorrect credentials. Attempts left: {3 - st.session_state.failed_attempts}")
            if st.session_state.failed_attempts >= 3:
                st.warning("🔒 Too many failed attempts. Please try again later.")

def store_data():
    if not st.session_state.current_user:
        st.warning("🔐 Please log in to continue.")
        return

    st.subheader("📂 Store Data Securely")
    user_data = st.text_area("Enter Data to Encrypt")
    if st.button("Encrypt & Save"):
        if user_data:
            encrypted = encrypt_data(user_data)
            if st.session_state.current_user not in stored_data:
                stored_data[st.session_state.current_user] = []
            stored_data[st.session_state.current_user].append(encrypted)
            save_data(stored_data)
            st.success("✅ Data stored securely!")
        else:
            st.error("⚠️ Data cannot be empty.")

def retrieve_data():
    if not st.session_state.current_user:
        st.warning("🔐 Please log in to continue.")
        return

    st.subheader("🔍 Retrieve Your Encrypted Data")
    if st.session_state.current_user in stored_data:
        encrypted_items = stored_data[st.session_state.current_user]
        for i, item in enumerate(encrypted_items, 1):
            st.write(f"Encrypted #{i}: {item}")
        selected = st.text_input("Paste the Encrypted Text to Decrypt")

        if st.button("Decrypt"):
            if selected in encrypted_items:
                try:
                    decrypted = decrypt_data(selected)
                    st.success(f"✅ Decrypted Data: {decrypted}")
                    st.session_state.failed_attempts = 0
                except:
                    st.session_state.failed_attempts += 1
                    st.error(f"❌ Failed to decrypt. Attempts left: {3 - st.session_state.failed_attempts}")
                    if st.session_state.failed_attempts >= 3:
                        st.warning("🔒 Too many failed attempts. Please log in again.")
                        st.session_state.current_user = None
            else:
                st.warning("⚠️ This encrypted data does not exist for your account.")
    else:
        st.info("ℹ️ You have no stored data yet.")

# Streamlit Sidebar Navigation
st.sidebar.title("🔐 Secure Data App")
menu = ["Signup", "Login", "Store Data", "Retrieve Data"]
choice = st.sidebar.selectbox("Go to", menu)

if choice == "Signup":
    signup()
elif choice == "Login":
    login()
elif choice == "Store Data":
    store_data()
elif choice == "Retrieve Data":
    retrieve_data()
