import streamlit as st
import hashlib
from cryptography.fernet import Fernet


KEY = Fernet.generate_key()
cipher = Fernet(KEY)


stored_data = {}
failed_attempts = 0


# function passkey

def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

# function to encrypt data


def encrypt_data(text, passkey):
    return cipher.encrypt(text.encode()).decode()


# function decrpt data

def decrypt_data(encrypted_text, passkey):
    global failed_attempts
    hashed_passkey = hash_passkey(passkey)

    for key, value in stored_data.items():
        if value["encrypted_text"] == encrypted_text and value["passkey"] == hashed_passkey:
            failed_attempts = 0
            return cipher.decrypt(encrypted_text.encode()).decode()

        failed_attempts += 1
        return None


#    app interface
menu = ["Home", "store_data", "Retrieve data", "Login"]
choice = st.sidebar.selectbox("Navigation", menu)


if choice == "Home":
    st.subheader("Welcome to the Secure Data System")
    st.write("Ues this app to  **securly store and retrieve data** useing passkey.")


elif choice == "store_data":
    st.subheader("Store Data securley")
    user_data = st.text_area("Enter data:")
    passkey = st.text_input("Enter Passkey:", type="password")

    if st.button("Encrypt & Save"):
        if user_data and passkey:
            hashed_passkey = hash_passkey(passkey)
            encrypted_text = encrypt_data(user_data, passkey)
            stored_data[encrypted_text] = {
                "encrypted_text": encrypted_text, "passkey": hashed_passkey}
            st.success("data stored Securely")
        else:
            st.error("Both fields are required")


elif choice == "Retrieve data":
    st.subheader("Retrieve Your data ")
    encrypted_text = st.text_area("Enter Encrypted data:")
    passkey = st.text_input("Enter Passkey:", type="password")

    if st.button("Decrypt"):
        if encrypted_text and passkey:
            decrypted_text = decrypt_data(encrypted_text, passkey)
            if decrypted_text:
                st.success(f"Decrypted Data: {decrypted_text}")
            else:
                st.error(
                    "Incorrect passkey Attempts remaining: {3 - failed_attempts}")

            if failed_attempts >= 3:
                st.warning(
                    "Too many failed attempts Redirecting to Login Page.")
                st.experimental_rerun()

            else:
                st.error("Both faileds are required")

elif choice == "Login":
    st.subheader("Reauthorization Required")
    login_pass = st.text_input("Enter Master Password:", type="password")
    if st.button("Login"):

        if login_pass == "admin123":
            failed_attempts = 0
            st.success(
                "Reauthorized successfully Redirecting to Retireve data...")
            st._experimental_rerun()
else:
    st.error("Incorrect Password")

