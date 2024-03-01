First you need to open your terminal and create project folder.
```py
mkdir fastapi_login_example
```

then cd to the created directory.
```
cd fastapi_login_example
````
then create your virtual environment.
```
python3 -m venv env
```

then if you are using vs code start it by typing
```py
code .
```
into command line.

we have simple directory structure 

config.py

db.py

dependencies.py

login.py

main.py

models.py

schemas.py


Actually they could all be in one file but if you want to use this as starter, it would be easier this way.

Our config.py have our environments variables.
These variables should be in a .env file and should be ignored by .gitignore.

config.py
```py

"""
These variables below needs to be changed and stored in .env file
and .env should be in .gitignore list so they are not checked into git
Then they could be loaded with the code below:
import os
from dotenv import load_dotenv
load_dotenv()

To create your own JWT_SECRET_KEY you can open up terminal and type ..
openssl rand -hex 32 on 01 dec 2023
Then you copoy/paste the result inside .env file like
JWT_SECRET_KEY = "resulting_key_from_terminal_goes_here"

"""


my_db_name = "fastapi_login_example_db"

SQLALCHEMY_DATABASE_URL = 'sqlite:///' + my_db_name
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60
REGISTER_TOKEN_EXPIRE_MINUTES = 10
REFRESH_TOKEN_EXPIRE_MINUTES = 43200
JWT_SECRET_KEY = "my_super_secret_jwt_key"
```

db.py has the db connection and engine initialization

```py
# Database handling is here
from sqlalchemy import create_engine, MetaData
from sqlalchemy.orm import sessionmaker, declarative_base
from config import SQLALCHEMY_DATABASE_URL


engine = create_engine(SQLALCHEMY_DATABASE_URL)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

```

dependencies.py

```py
from db import SessionLocal

# Dependencies
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
```

login.py
```py
from datetime import datetime, timedelta, timezone  
from typing import Annotated
from sqlalchemy.orm import Session
from fastapi import Depends, APIRouter, HTTPException, Security, status
from fastapi.security import (
    OAuth2PasswordBearer,
    OAuth2PasswordRequestForm,
    SecurityScopes,
)
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import ValidationError
from starlette.responses import JSONResponse
from dependencies import get_db
from config import (
    ACCESS_TOKEN_EXPIRE_MINUTES,
    REFRESH_TOKEN_EXPIRE_MINUTES,
    REGISTER_TOKEN_EXPIRE_MINUTES,
    JWT_SECRET_KEY,
    ALGORITHM,
)
from schemas import User, Token, TokenData
import models, schemas
import re


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_user_scheme = OAuth2PasswordBearer(
    tokenUrl="/login/token",
    scheme_name="oauth2_user_scheme",
    scopes={"user": "allowed methods for authenticated users"},
)

user_login_router = APIRouter(prefix="/login", tags=["login"])


def check_password(password:str):
    """
    Verify the strength of 'password'
    Returns a dict indicating the wrong criteria
    A password is considered strong if:
        8 characters length or more
        1 digit or more
        1 symbol or more
        1 uppercase letter or more
        1 lowercase letter or more
    """

    # calculating the length
    length_error = len(password) < 8

    # searching for digits
    digit_error = re.search(r"\d", password) is None

    # searching for uppercase
    uppercase_error = re.search(r"[A-Z]", password) is None

    # searching for lowercase
    lowercase_error = re.search(r"[a-z]", password) is None

    # searching for symbols
    symbol_error = re.search(r"[ !#$%&'()*+,-./[\\\]^_`{|}~"+r'"]', password) is None

    # overall result
    password_ok = not ( length_error or digit_error or uppercase_error or lowercase_error or symbol_error )

    return {
        'password_ok' : password_ok,
        'length_error' : length_error,
        'digit_error' : digit_error,
        'uppercase_error' : uppercase_error,
        'lowercase_error' : lowercase_error,
        'symbol_error' : symbol_error,
    }


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def create_user(db: Session, user: schemas.RegisterUser):
    """creates a user with schemas.CreateUser attributes"""
    hashed_password = get_password_hash(user.password)
    user = models.User(
        is_active = user.is_active,
        email=user.email,
        password=hashed_password
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def get_user(db: Session, user_id: int):
    """retuns the user with user_id: int"""
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if user is not None:
        return user
    else:
        return False


def get_user_by_email(db: Session, user_email: str):
    """retuns the user with user_id: int"""
    user = db.query(models.User).filter(models.User.email == user_email).first()
    if user is not None:
        return user
    else:
        return False


def authenticate_user(email: str, password: str, db: Session = Depends(get_db)):
    user = get_user_by_email(db, email)
    if not user:
        return False
    if not verify_password(password, user.password):
        return False
    return user


def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(
            minutes=float(ACCESS_TOKEN_EXPIRE_MINUTES)
        )
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def create_refresh_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(
            minutes=float(REFRESH_TOKEN_EXPIRE_MINUTES)
        )
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(
    security_scopes: SecurityScopes,
    token: Annotated[str, Depends(oauth2_user_scheme)],
    db: Session = Depends(get_db),
):
    if security_scopes.scopes:
        authenticate_value = f'Bearer scope="{security_scopes.scope_str}"'
    else:
        authenticate_value = "Bearer"
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[ALGORITHM])
        id: str = payload.get("id")
        if id is None:
            raise credentials_exception
        token_scopes = payload.get("scopes", [])
        token_data = TokenData(id=id, scopes=token_scopes)
    except (JWTError, ValidationError):
        raise credentials_exception
    user = get_user(db, token_data.id )
    if user is None:
        raise credentials_exception
    for scope in security_scopes.scopes:
        if scope not in token_data.scopes:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Not enough permissions",
                headers={"WWW-Authenticate": authenticate_value},
            )
    return user


async def get_current_active_user(
    current_user: Annotated[User, Security(get_current_user)]
):
    if not current_user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


@user_login_router.post("/register")
def register_user_for_acess(
    form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)
):
    password_ok = check_password(form_data.password)
    if not password_ok["password_ok"]:
        pw_errors:dict = {}
        for key, value in password_ok.items():
            if not value:
                pw_errors[key] = value
        print(pw_errors)
        raise HTTPException(
            status_code=400, detail="Password does not meet requirements"
        )

    user = get_user_by_email(db, form_data.username)
    print(user)
    if not user:
        user_to_reg = schemas.RegisterUser(
            is_active=1,
            email=form_data.username,
            password=form_data.password
        )
        user_to_cr = create_user(db, user_to_reg)
        jwt_data: dict = {
            "id": str(user_to_cr.id),
            "email": str(user_to_cr.email),
        }
        access_token_expires = timedelta(minutes=float(REGISTER_TOKEN_EXPIRE_MINUTES))
        a_t: str = create_access_token(jwt_data, access_token_expires)

        message: str = f"User {user_to_cr.email} was created successfully"
        return JSONResponse(status_code=201, content={"message": message})

    else:
        raise HTTPException(
            status_code=400, detail="User with this email already exists!"
        )
    

@user_login_router.post("/token", response_model=Token)
async def login_for_access_token(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db),
):
    user = authenticate_user(form_data.username, form_data.password, db)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=float(ACCESS_TOKEN_EXPIRE_MINUTES))
    access_token = create_access_token(
        data={"id": str(user.id), "scopes": form_data.scopes},
        expires_delta=access_token_expires,
    )
    refresh_token_expires = timedelta(minutes=float(REFRESH_TOKEN_EXPIRE_MINUTES))
    refresh_token = create_refresh_token(
        data={"id": str(user.id), "scopes": form_data.scopes},
        expires_delta=refresh_token_expires,
    )

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "Bearer",
    }


@user_login_router.get("/me/", response_model=User)
async def read_users_me(
    current_user: Annotated[User, Security(get_current_active_user)]
):
    return current_user

```

main.py
```py
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

```

models.py
```py
from sqlalchemy import (
    Column,
    Integer,
    String,
)
from db import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    is_active = Column
    email = Column(String(50), unique=True, index=False)
    password = Column(String(255))

```

schemas.py
```py
from datetime import datetime
from pydantic import BaseModel

class RegisterUser(BaseModel):
    is_active: int
    email:str
    password:str

class User(RegisterUser):
    id: int

class Token(BaseModel):
    access_token: str | None
    refresh_token: str | None
    token_type: str

class TokenData(BaseModel):
    id: str | None = None
    scopes: list[str] = []


```

Please give stars if it helps you
