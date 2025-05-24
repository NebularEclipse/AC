# 🔐 CryptoSeal

**Course:** CSAC 329 - Applied Cryptography
**Date:** May 24, 2025

## 👥 Group Members (aBitLocK Bros)
- Bata, Gian Carlo -  - (NebularEclipse, Carb0n-17)
- Calingacion, Almira - (Almira2303)
- Papa, Nikko
- Tagum, Leo - (Sauzzen)

---

## 📌 Introduction
CryptoSeal is a web-based cryptographic toolkit for encrypting, decrypting, and hashing text and files. Built to demonstrate practical cryptographic applications, it emphasizes data privacy and integrity in today's digital landscape.


## 🎯 Project Objectives
1. Implement 3 symmetric and 2 asymmetric encryption algorithms
2. Provide 4 hashing functions for text and file verification.
3. Integrate user roles, address management via PSGC API, and rate limiting for enhanced usability and security.
---

## Discussions
### 🧱 Application Architecture & UI
- **Backend:**
- Language/Framework: Python (Flask)
- Database: SQLite
- Logic: Modular structure under logic/ directory
- **Frontend:**
- HTML/CSS/JS
- Sidebar-based navigation and clean UI/UX
- **UI Choice:**
- Clean, intuitive dashboard with clear separation of cryptographic tools and user/account management.

### 🔐 Implemented Cryptographic Algorithms
### 🔄 Symmetric Encryption
| Algorithm    | Library                         | Notes                          
| ------------ | ------------------------------- | ------------------------------|
| **AES**      | `cryptography` / `pycryptodome` | Standard secure encryption (text & files) |
| **DES**      | `pycryptodome`                  | Legacy algorithm, included for comparison |
| **ChaCha20** | `pycryptodome`                  | Fast and modern stream cipher |


#### 🔐 Asymmetric Encryption
| Algorithm | Library                         | Notes                                      |
| --------- | ------------------------------- | --------------------------------|
| **RSA**   | `cryptography` / `pycryptodome` | Secure key exchange, text encryption       |
| **ECC**   | `cryptography`                  | Efficient and modern, key-based encryption |


#### 🧾 Hashing Functions
| Function    | Library   | Notes                               |
| ----------- | --------- | ----------------------------------- |
| **SHA-256** | `hashlib` | Secure and standard                 |
| **MD5**     | `hashlib` | Fast but insecure (educational use) |
| **SHA-1**   | `hashlib` | Legacy, not secure                  |
| **BLAKE2**  | `hashlib` | Modern, high performance            |


---

## 🖼️ Sample Outputs
- Screenshots and code output examples will be provided for each algorithm's encryption, decryption, and hashing (text and file). See `/Mockup/` and UI screenshots in the repository.

---

## ✨ Features
- Encrypt/decrypt text and files (symmetric & asymmetric)
- Hash text/files using standard algorithms
- Role-based authentication (Admin, User)
- PSGC API integration for address validation
- Rate limiting to prevent abuse

## 🚀 Getting Started
### ✅ Prerequisites
- Python 3.8+
- pip package manager

### Database Setup
1. Initialize the database:
   ```powershell
   flask --app app init-db
   ```
2. Schema: see `app/schema.sql` for database schema.

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
- Open your browser: `http://127.0.0.1:5000/`
- Use the sidebar to select cryptographic tools
- Input text or upload files for encryption, decryption, or hashing

## 👤 User Roles
| Role      | Description                                                |
| --------- | ---------------------------------------------------------- |
| **Admin** | Full access: cryptographic tools + user/account management |
| **User**  | Limited access: encryption, decryption, address tools      |


## 📍 Address Management (PSGC API)
- Integrates Philippine Standard Geographic Code (PSGC) API for precise address handling and validation.

🧰 Technologies Used
- Languages/Frameworks: Python, Flask, HTML, CSS, JavaScript
- Database: SQLite

## 📚 Python Libraries

- **pyca/cryptography:** Core cryptographic primitives and recipes for encryption, decryption, and key management.
- **PyCryptodome:** Self-contained Python package of low-level cryptographic primitives (AES, DES, ChaCha20, RSA, etc.).
- **Cryptocode:** Simple library for symmetric and asymmetric encryption, used for educational examples.
- **RSA:** Python library for RSA key generation, encryption, and decryption.
- **hashlib:** Standard Python library for hashing algorithms (SHA-256, SHA-1, MD5, BLAKE2).
- **pyaes:** Pure-Python implementation of AES, used for demonstration and testing.


## Rate Limiting
- Prevents abuse by limiting requests per user/IP (Flask-Limiter or similar)

## License
This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
