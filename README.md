# CrytoConvert

**Course:** CSAC 329 - Applied Cryptography - 2024-25-2  
**Date:** May 24, 2025

## Group Members
- Bata, Gian Carlo
- Calingacion, Almira
- Papa, Nikko
- Tagum, Leo

---

## Introduction
CrytoConvert is a web-based cryptography toolkit designed to help users securely encrypt, decrypt, and hash both text and files using a variety of modern cryptographic algorithms. The project aims to demonstrate the practical application of cryptography in protecting data privacy and integrity, highlighting its importance in today's digital world.

## Project Objectives
1. Implement 3 symmetric and 2 asymmetric encryption algorithms for text and file security.
2. Provide 4 hashing functions for both text and file integrity verification.
3. Integrate user roles, address management (with PSGC API), and rate limiting for a secure, user-friendly experience.

---

## Discussions
### Application Architecture & UI
- **Backend:** Python (Flask), SQLite for data storage, modular logic for cryptographic operations.
- **Frontend:**  HTML/CSS/JS, modern sidebar navigation.
- **UI Choice:** Clean, intuitive dashboard with clear separation of cryptographic tools and user/account management.

### Implemented Cryptographic Algorithms
#### Symmetric Algorithms
- **AES (Advanced Encryption Standard)**
  - *Type:* Symmetric
  - *Background:* Widely used standard for secure data encryption.
  - *Process:* Uses a shared secret key for both encryption and decryption. Supports text and file operations.
  - *Library:* `cryptography` or `pycryptodome`
  - *Integration:* Backend logic in `logic/symmetric.py`, accessible via web UI.
- **DES (Data Encryption Standard)**
  - *Type:* Symmetric
  - *Background:* Early standard, now less secure but included for educational purposes.
  - *Process:* Block cipher with 56-bit key, used for text and file encryption/decryption.
  - *Library:* `pycryptodome`
  - *Integration:* Backend logic, selectable in UI.
- **Blowfish**
  - *Type:* Symmetric
  - *Background:* Fast block cipher, flexible key length.
  - *Process:* Encrypts/decrypts data in blocks, suitable for files and text.
  - *Library:* `pycryptodome`
  - *Integration:* Backend logic, selectable in UI.

#### Asymmetric Algorithms
- **RSA**
  - *Type:* Asymmetric
  - *Background:* Popular for secure key exchange and digital signatures.
  - *Process:* Uses public/private key pairs for text encryption/decryption.
  - *Library:* `cryptography` or `pycryptodome`
  - *Integration:* Logic in `logic/asymmetric.py`, UI for key management and encryption.
- **ECC (Elliptic Curve Cryptography)**
  - *Type:* Asymmetric
  - *Background:* Modern, efficient alternative to RSA.
  - *Process:* Uses elliptic curve math for secure text encryption/decryption.
  - *Library:* `cryptography`
  - *Integration:* Logic in `logic/asymmetric.py`, UI for key management and encryption.

#### Hashing Functions
- **SHA-256**
  - *Type:* Hash
  - *Background:* Secure hash standard, widely used for data integrity.
  - *Process:* Produces a 256-bit hash for text or files.
  - *Library:* `hashlib`
  - *Integration:* Logic in `logic/hashing.py`, UI for text/file hashing.
- **MD5**
  - *Type:* Hash
  - *Background:* Fast, but not collision-resistant; included for legacy/educational use.
  - *Process:* Produces a 128-bit hash.
  - *Library:* `hashlib`
  - *Integration:* Logic in `logic/hashing.py`.
- **SHA-1**
  - *Type:* Hash
  - *Background:* Older standard, now considered weak.
  - *Process:* Produces a 160-bit hash.
  - *Library:* `hashlib`
  - *Integration:* Logic in `logic/hashing.py`.
- **BLAKE2**
  - *Type:* Hash
  - *Background:* Modern, fast, and secure hash function.
  - *Process:* Produces variable-length hash.
  - *Library:* `hashlib`
  - *Integration:* Logic in `logic/hashing.py`.

---

## Sample Runs/Outputs
- Screenshots and code output examples will be provided for each algorithm's encryption, decryption, and hashing (text and file). See `/Mockup/` and UI screenshots in the repository.

---

## Features
- Encrypt/decrypt text and files (symmetric & asymmetric)
- Hash text and files
- User authentication and roles
- Address management with PSGC API
- Rate limiting for security

## Getting Started
### Prerequisites
- Python 3.8+
- pip

### Database Setup
1. Initialize the database:
   ```powershell
   flask --app app init-db
   ```
2. Schema: see `app/schema.sql`

### Installation
1. Clone the repository:
   ```powershell
   git clone <repo-url>
   cd AC
   ```
2. Install dependencies:
   ```powershell
   pip install -r requirements.txt
   ```
3. Run the app:
   ```powershell
   flask --app app run
   ```

## Usage
- Access at `http://127.0.0.1:5000/`
- Use the sidebar to select cryptographic tools
- Upload files or enter text for operations

## User Roles
- **Admin:** Full access, user management
- **User:** Cryptography tools, address management

## Address Management with PSGC API
- Integrates with the Philippine Standard Geographic Code API for address validation and management

## Technologies Used
- Python, Flask, SQLite, HTML, CSS, JavaScript

## Python Libraries and Tools Used

- **pyca/cryptography:** Core cryptographic primitives and recipes for encryption, decryption, and key management.
- **PyCryptodome:** Self-contained Python package of low-level cryptographic primitives (AES, DES, Blowfish, RSA, etc.).
- **Cryptocode:** Simple library for symmetric and asymmetric encryption, used for educational examples.
- **RSA:** Python library for RSA key generation, encryption, and decryption.
- **hashlib:** Standard Python library for hashing algorithms (SHA-256, SHA-1, MD5, BLAKE2).
- **pyaes:** Pure-Python implementation of AES, used for demonstration and testing.


## Rate Limiting
- Prevents abuse by limiting requests per user/IP (Flask-Limiter or similar)

## License
This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.