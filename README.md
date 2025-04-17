# 🔒 Secure Data Encryption System

A Streamlit-based application for secure data storage and retrieval using strong encryption.

## Features

- 🔐 Strong encryption using Fernet (symmetric encryption)
- 🔑 Secure passkey hashing with PBKDF2
- ⏱️ Automatic lockout after multiple failed attempts
- 💾 Persistent data storage in JSON format
- 🎨 Modern and user-friendly interface

## Prerequisites

- Python 3.7 or higher
- pip (Python package installer)

## Installation

1. Clone this repository or download the source code
2. Install the required packages:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

1. Run the application:
   ```bash
   streamlit run app.py
   ```

2. Open your web browser and navigate to the URL shown in the terminal (usually http://localhost:8501)

3. Use the navigation sidebar to:
   - Store new data
   - Retrieve existing data
   - Login (if locked out)

## Security Features

- Data is encrypted using Fernet (symmetric encryption)
- Passkeys are hashed using PBKDF2 with SHA-256
- Automatic lockout after 3 failed attempts
- 5-minute lockout duration
- Persistent storage in encrypted format

## Important Notes

- The master password for the login page is set to "admin123" (change this in production)
- Always keep your encrypted data and passkey safe
- The application uses a .env file to store the encryption key
- Data is stored in encrypted_data.json

## Customization

You can modify the following constants in app.py:
- `MAX_ATTEMPTS`: Number of allowed failed attempts
- `LOCKOUT_DURATION`: Duration of lockout in seconds
- `DATA_FILE`: Name of the data storage file

## Security Considerations

For production use:
1. Change the master password
2. Implement proper user authentication
3. Use environment variables for sensitive data
4. Consider adding rate limiting
5. Implement proper session management

## License

This project is open source and available under the MIT License. 