import streamlit as st
import hashlib
import json
import time
from cryptography.fernet import Fernet
import base64

# Custom CSS for dark color scheme and layout
st.markdown(
    """
    <style>
    /* Dark background and light text colors */
    .main {
        background-color: #121212;
        color: #e0e0e0;
    }
    .stButton>button {
        background-color: #1f6feb;
        color: white;
        border-radius: 8px;
        height: 40px;
        width: 100%;
        font-weight: bold;
        font-size: 16px;
        margin-top: 10px;
        margin-bottom: 10px;
        border: none;
    }
    .stButton>button:hover {
        background-color: #155ab6;
        color: white;
    }
    .stTextInput>div>div>input, .stTextArea>div>textarea {
        background-color: #1e1e1e;
        color: #e0e0e0;
        border-radius: 6px;
        border: 1px solid #444444;
        padding: 8px;
        font-size: 14px;
    }
    .stTextInput>div>div>input:focus, .stTextArea>div>textarea:focus {
        border: 1.5px solid #1f6feb;
        outline: none;
        background-color: #1e1e1e;
        color: #e0e0e0;
    }
    .stMarkdown h1, .stMarkdown h2, .stMarkdown h3 {
        color: #1f6feb;
        font-weight: 700;
    }
    .footer {
        text-align: center;
        color: #888888;
        font-size: 14px;
        margin-top: 40px;
        padding-top: 10px;
        border-top: 1px solid #333333;
    }
    .info-box {
        background-color: #263238;
        border-left: 6px solid #1f6feb;
        padding: 10px 15px;
        margin-bottom: 15px;
        border-radius: 4px;
        color: #e0e0e0;
    }
    .stAlert {
        background-color: #263238 !important;
        color: #e0e0e0 !important;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

# Initialize session state variables if they don't exist
if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0
if 'stored_data' not in st.session_state:
    st.session_state.stored_data = {}
if 'current_page' not in st.session_state:
    st.session_state.current_page = "Home"
if 'last_attempt_time' not in st.session_state:
    st.session_state.last_attempt_time = 0

# Function to hash passkey
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

# Function to generate a key from passkey (for encryption)
def generate_key_from_passkey(passkey):
    # Use the passkey to create a consistent key
    hashed = hashlib.sha256(passkey.encode()).digest()
    # Ensure it's valid for Fernet (32 url-safe base64-encoded bytes)
    return base64.urlsafe_b64encode(hashed[:32])

# Function to encrypt data
def encrypt_data(text, passkey):
    key = generate_key_from_passkey(passkey)
    cipher = Fernet(key)
    return cipher.encrypt(text.encode()).decode()

# Function to decrypt data
def decrypt_data(encrypted_text, passkey, data_id):
    try:
        # Check if the passkey matches
        hashed_passkey = hash_passkey(passkey)
        if data_id in st.session_state.stored_data and st.session_state.stored_data[data_id]["passkey"] == hashed_passkey:
            # If passkey matches, decrypt the data
            key = generate_key_from_passkey(passkey)
            cipher = Fernet(key)
            decrypted = cipher.decrypt(encrypted_text.encode()).decode()
            st.session_state.failed_attempts = 0
            return decrypted
        else:
            # Increment failed attempts
            st.session_state.failed_attempts += 1
            st.session_state.last_attempt_time = time.time()
            return None
    except Exception as e:
        # If decryption fails, increment failed attempts
        st.session_state.failed_attempts += 1
        st.session_state.last_attempt_time = time.time()
        return None

# Function to generate a unique ID for data
def generate_data_id():
    import uuid
    return str(uuid.uuid4())

# Function to reset failed attempts
def reset_failed_attempts():
    st.session_state.failed_attempts = 0

# Function to change page
def change_page(page):
    st.session_state.current_page = page

# Streamlit UI
st.title("🔒 Secure Data Encryption System")

# Sidebar Navigation with color styling
menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.radio("Navigation", menu, index=menu.index(st.session_state.current_page))
st.session_state.current_page = choice

# Check if too many failed attempts
if st.session_state.failed_attempts >= 3:
    # Force redirect to login page
    st.session_state.current_page = "Login"
    st.warning("🔒 Too many failed attempts! Reauthorization required.")

# Display current page
if st.session_state.current_page == "Home":
    st.subheader("🏠 Welcome to the Secure Data System")
    st.write("Use this app to **securely store and retrieve data** using unique passkeys.")
    
    st.markdown("---")
    col1, col2 = st.columns(2)
    with col1:
        if st.button("Store New Data", use_container_width=True):
            change_page("Store Data")
    with col2:
        if st.button("Retrieve Data", use_container_width=True):
            change_page("Retrieve Data")
    
    st.markdown("---")
    st.markdown('<div class="info-box">Currently storing <b>{}</b> encrypted data entries.</div>'.format(len(st.session_state.stored_data)), unsafe_allow_html=True)

elif st.session_state.current_page == "Store Data":
    st.subheader("📂 Store Data Securely")
    user_data = st.text_area("Enter Data:", help="Enter the text data you want to encrypt and store securely.")
    passkey = st.text_input("Enter Passkey:", type="password", help="Enter a passkey to encrypt your data.")
    confirm_passkey = st.text_input("Confirm Passkey:", type="password", help="Re-enter the passkey to confirm.")

    if st.button("Encrypt & Save"):
        if user_data and passkey and confirm_passkey:
            if passkey != confirm_passkey:
                st.error("⚠️ Passkeys do not match!")
            else:
                # Generate a unique ID for this data
                data_id = generate_data_id()
                
                # Hash the passkey
                hashed_passkey = hash_passkey(passkey)
                
                # Encrypt the data
                encrypted_text = encrypt_data(user_data, passkey)
                
                # Store in the required format
                st.session_state.stored_data[data_id] = {
                    "encrypted_text": encrypted_text,
                    "passkey": hashed_passkey
                }
                
                st.success("✅ Data stored securely!")
                
                # Display the data ID for retrieval
                st.code(data_id, language="text")
                st.info("⚠️ Save this Data ID! You'll need it to retrieve your data.")
        else:
            st.error("⚠️ All fields are required!")

elif st.session_state.current_page == "Retrieve Data":
    st.subheader("🔍 Retrieve Your Data")
    
    # Show attempts remaining
    attempts_remaining = 3 - st.session_state.failed_attempts
    st.markdown('<div class="info-box">Attempts remaining: <b>{}</b></div>'.format(attempts_remaining), unsafe_allow_html=True)
    
    data_id = st.text_input("Enter Data ID:", help="Enter the unique Data ID you received when storing your data.")
    passkey = st.text_input("Enter Passkey:", type="password", help="Enter the passkey used to encrypt the data.")

    if st.button("Decrypt"):
        if data_id and passkey:
            if data_id in st.session_state.stored_data:
                encrypted_text = st.session_state.stored_data[data_id]["encrypted_text"]
                decrypted_text = decrypt_data(encrypted_text, passkey, data_id)

                if decrypted_text:
                    st.success("✅ Decryption successful!")
                    st.markdown("### Your Decrypted Data:")
                    st.code(decrypted_text, language="text")
                else:
                    st.error(f"❌ Incorrect passkey! Attempts remaining: {3 - st.session_state.failed_attempts}")
            else:
                st.error("❌ Data ID not found!")
                
            # Check if too many failed attempts after this attempt
            if st.session_state.failed_attempts >= 3:
                st.warning("🔒 Too many failed attempts! Redirecting to Login Page.")
                st.session_state.current_page = "Login"
                st.experimental_rerun()
        else:
            st.error("⚠️ Both fields are required!")

elif st.session_state.current_page == "Login":
    st.subheader("🔑 Reauthorization Required")
    
    # Add a simple timeout mechanism
    timeout_seconds = 10
    time_since_last_attempt = time.time() - st.session_state.last_attempt_time
    if time_since_last_attempt < timeout_seconds and st.session_state.failed_attempts >= 3:
        remaining_time = int(timeout_seconds - time_since_last_attempt)
        st.warning(f"🕒 Please wait {remaining_time} seconds before trying again.")
        login_disabled = True
    else:
        login_disabled = False

    login_pass = st.text_input("Enter Master Password:", type="password")

    if st.button("Login", disabled=login_disabled):
        if login_pass == "admin123":  # Hardcoded for demo, replace with proper auth
            reset_failed_attempts()
            st.success("✅ Reauthorized successfully!")
            st.session_state.current_page = "Home"
            st.experimental_rerun()
        else:
            st.error("❌ Incorrect password!")

# Add a styled footer
st.markdown('<div class="footer">🔐 Secure Data Encryption System | Educational Project</div>', unsafe_allow_html=True)
