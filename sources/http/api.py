from fastapi import FastAPI, HTTPException
from pydantic import BaseModel


app = FastAPI(
    title="IDS Test HTTP API",
    description="HTTP server used for IDS attack testing",
    version="1.0.0",
)


# Test users

USERS = {
    "admin": "password",
    "alexei": "barber",
    "john": "password1",
    "root": "qwerty",
}



# Request models


class LoginRequest(BaseModel):
    username: str
    password: str


# Authentication endpoint


@app.post("/api/auth/login")
def login(credentials: LoginRequest):
    expected_password = USERS.get(credentials.username)

    if expected_password is None:
        raise HTTPException(
            status_code=401,
            detail="Invalid username or password",
        )

    if credentials.password != expected_password:
        raise HTTPException(
            status_code=401,
            detail="Invalid username or password",
        )

    return {
        "success": True,
        "message": "Authentication successful",
        "username": credentials.username,
    }



# Health endpoint


@app.get("/api/health")
def health():
    return {
        "status": "ok",
    }



# Mock data endpoint


@app.get("/api/data")
def get_data():
    return {
        "id": 1,
        "name": "IDS Test Resource",
        "description": "Mock data",
        "status": "active",
    }



# Root endpoint


@app.get("/")
def root():
    return {
        "service": "IDS Test HTTP API",
        "status": "running",
    }
