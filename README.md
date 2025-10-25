# User Service

gRPC-based microservice for user account management with authentication, password reset, and session management.

## Quick Start

### 1. Setup Environment Variables

```bash
cp .env.example .env
```

Edit `.env` with your configuration (JWT secret, SMTP credentials, etc.)

### 2. Running with CLI

**Install dependencies:**
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

**Generate gRPC stubs:**
```bash
./generate_grpc.sh
```

**Run the service:**
```bash
python main.py
```

Service will start on `localhost:50051`

### 3. Running with Docker

```bash
docker compose up
```

This starts both the user service and PostgreSQL database.

## Features

- **SignUp** - User registration with email validation
- **SignIn** - Authentication with JWT token generation
- **ValidateToken** - JWT token validation and session checking
- **GetUser** - Retrieve user information by ID
- **ResetPassword** - Send password reset email
- **ConfirmPasswordReset** - Complete password reset flow
- **Logout** - Revoke user session

## Tech Stack

- gRPC / Protocol Buffers
- SQLAlchemy (PostgreSQL / SQLite)
- PyJWT for authentication
- bcrypt for password hashing
- SMTP for email notifications
