#  JWT Auth API – Node.js + Express

This is a backend REST API for user authentication built with **Node.js**, **Express**, and **JWT**.  
It supports user registration, login, and token-protected routes — perfect for modern auth workflows.





## Features

-  Secure user registration (with bcrypt-hashed passwords)
-  User login with signed JWT token generation
-  Protected route access using `Authorization: Bearer <token>`
-  Local JSON-based user persistence (`users.json`)
-  `.env` support for secret config
-  Health check endpoint for uptime monitoring

---

##  Tech Stack

- **Runtime:** Node.js
- **Framework:** Express.js
- **Auth:** JSON Web Tokens (`jsonwebtoken`)
- **Password Hashing:** bcryptjs
- **Data Storage:** File-based (`fs`) for demo purposes
- **Environment Config:** dotenv

---

##  Getting Started

### 1. Clone the Project

```bash ``
``git clone `` https://github.com/sassante/-JWT-Auth-API-Node.js-Express ``
cd node-jwt-auth-api

### 2. Install Dependencies
npm install

 ### 3. Start the Server
 npm run dev

## API Endpoints
 ### POST /register
Registers a new user.
 Body: {
  "username": "nova_dev",
  "password": "MyStrongP@ss123"
}

## POST /login
Logs in and returns a signed JWT.

Body:{
  "username": "nova_dev",
  "password": "MyStrongP@ss123"
}

 ## Response:
{
  "message": "Login successful",
  "token": "your.jwt.token",
  "expiresIn": "15m",
  "user": {
    "id": "abc123",
    "username": "nova_dev",
    "createdAt": "2025-07-17T10:00:00.000Z"
  }
}

## GET /profile (Protected)
 ## Requires a valid JWT in the header.

Header: 
Authorization: Bearer your.jwt.token

## GET /health
 ##Returns a basic health check response.

## Response:
{
  "status": "OK",
  "timestamp": "2025-07-17T10:00:00.000Z",
  "message": "JWT Authentication API is running"
}

## Important Notes
File-based storage (users.json) is for demo only — use a real database (like MongoDB or PostgreSQL) in production.

Always change the JWT_SECRET and use HTTPS in deployed apps.

Consider adding token refresh logic and rate limiting for enhanced security.






