from fastapi import FastAPI
from fastapi.security import  OAuth2PasswordBearer
from passlib.context import CryptContext
from login import user_login_router
from db import Base, engine

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_user_scheme = OAuth2PasswordBearer(
    tokenUrl="/user/login/token",
    scheme_name="oauth2_user_scheme",
    scopes={"user": "allowed methods for authenticated users"},
)

app = FastAPI()
app.include_router(user_login_router)
Base.metadata.create_all(bind=engine)


@app.get("/")
async def root():
    return {"message": "Please login to use API"}

