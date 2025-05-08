from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
from pydantic import BaseModel
import uuid
import os

# Конфигурация
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-CHANGE-ME")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

app = FastAPI()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Хранилище в памяти
users = {}  # {username: {"email": str, "hashed_password": str, "is_banned": bool, "is_admin": bool, "created_at": datetime}}
keys = {}   # {key: {"user_id": str, "is_activated": bool, "created_at": datetime}}

# Инициализация начального пользователя (admin)
initial_user = {
    "username": "dev",
    "email": "dev@example.com",
    "password": "number888"
}
if "dev" not in users:
    users["dev"] = {
        "email": initial_user["email"],
        "hashed_password": pwd_context.hash(initial_user["password"]),
        "is_banned": False,
        "is_admin": True,
        "created_at": datetime.utcnow()
    }

# Pydantic модели
class UserCreate(BaseModel):
    username: str
    email: str
    password: str
    is_admin: bool = False  # По умолчанию обычный пользователь

class KeyResponse(BaseModel):
    key: str
    is_activated: bool

# JWT
def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    user = users.get(username)
    if user is None or user["is_banned"]:
        raise HTTPException(status_code=401, detail="User not found or banned")
    return user

async def get_current_admin_user(token: str = Depends(oauth2_scheme)):
    user = await get_current_user(token)
    if not user.get("is_admin", False):
        raise HTTPException(status_code=403, detail="Admin access required")
    return user

# API endpoints
@app.post("/register")
def register(user: UserCreate, current_user: dict = Depends(get_current_admin_user)):
    if user.username in users:
        raise HTTPException(status_code=400, detail="Username already exists")
    for u in users.values():
        if u["email"] == user.email:
            raise HTTPException(status_code=400, detail="Email already exists")
    hashed_password = pwd_context.hash(user.password)
    users[user.username] = {
        "email": user.email,
        "hashed_password": hashed_password,
        "is_banned": False,
        "is_admin": user.is_admin,
        "created_at": datetime.utcnow()
    }
    return {"message": f"User {user.username} registered {'as admin' if user.is_admin else 'as regular user'} successfully"}

@app.post("/token")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = users.get(form_data.username)
    if not user or not pwd_context.verify(form_data.password, user["hashed_password"]):
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    if user["is_banned"]:
        raise HTTPException(status_code=403, detail="User is banned")
    access_token = create_access_token(data={"sub": form_data.username})
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/generate-key")
def generate_key(current_user: dict = Depends(get_current_user)):
    key = "-".join([str(uuid.uuid4())[:5].upper() for _ in range(5)])
    keys[key] = {
        "user_id": current_user["email"],
        "is_activated": False,
        "created_at": datetime.utcnow()
    }
    return {"key": key}

@app.post("/activate-key")
def activate_key(key: str, current_user: dict = Depends(get_current_user)):
    db_key = keys.get(key)
    if not db_key:
        raise HTTPException(status_code=404, detail="Key not found")
    if db_key["is_activated"]:
        raise HTTPException(status_code=400, detail="Key already activated")
    if db_key["user_id"] != current_user["email"]:
        raise HTTPException(status_code=403, detail="Key belongs to another user")
    db_key["is_activated"] = True
    return {"message": "Key activated successfully"}

@app.post("/ban-user")
def ban_user(username: str, current_user: dict = Depends(get_current_admin_user)):
    user = users.get(username)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    user["is_banned"] = True
    return {"message": f"User {username} banned"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
