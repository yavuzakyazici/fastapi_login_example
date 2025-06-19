# 🔐 FastAPI Login Example with JWT & Refresh Tokens

A minimal but production-ready login system built with **FastAPI**, **Pydantic**, and **JWT Authentication**.  
Demonstrates key security flows such as token creation, refresh, blacklist handling, and basic user management.

---

## 🛠 Tech Stack

- **FastAPI** – Fast and modern Python web framework
- **Pydantic** – Data validation and parsing
- **JWT** – JSON Web Tokens for authentication
- **Passlib** – Secure password hashing
- **SQLite** – Lightweight DB for demo purposes

---

## 📂 Features

- Email + password login
- JWT access & refresh token generation
- Refresh token endpoint with blacklist logic
- Password hashing and verification
- Pydantic models for validation and type safety
- Basic `/protected` route secured by access token

---

## 🚀 Getting Started

```bash
git clone https://github.com/yavuzakyazici/fastapi_login_example.git
cd fastapi_login_example
python -m venv venv
source venv/bin/activate   # On Windows: venv\Scripts\activate
pip install -r requirements.txt
uvicorn main:app --reload
```
Visit: http://localhost:8000/docs for Swagger UI

🔁 Token Flow Diagram

```txt
Login (email+password)
   ↓
Generate Access Token (short-lived)
   ↓
Generate Refresh Token (long-lived)
   ↓
Use Refresh Token to get new Access Token
   ↓
Blacklist old refresh token after use (secure)
```

🧪 Example Requests
```bash
POST /login
{
  "email": "test@example.com",
  "password": "123456"
}
```

Access Protected Route
```bash
GET /protected
Headers: Authorization: Bearer <access_token>
```

Refresh Token
```bash
POST /refresh
{
  "refresh_token": "<refresh_token>"
}
```

📎 Notes
```list
* Tokens use UUID-based payloads and expiration claims.
* Includes verify_password() and hash_password() helpers.
* Modular structure allows for expansion with user roles, email verification, etc.
```

📁 Part of Developer Portfolio
This project is one of several focused FastAPI examples by [Yavuz Akyazıcı](https://github.com/yavuzakyazici), creator of JAM – Jazz A Minute app [iOS](https://apps.apple.com/app/j-a-m/id6504705021) and [Android](https://play.google.com/store/apps/details?id=com.jazzaminute).

For a more complete backend demo with admin panel, analytics, and cloud storage, contact directly.


