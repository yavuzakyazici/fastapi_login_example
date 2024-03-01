from sqlalchemy import (
    Column,
    Integer,
    String,
)
from db import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    is_active = Column(Integer)
    email = Column(String(50), unique=True, index=False)
    password = Column(String(255))

