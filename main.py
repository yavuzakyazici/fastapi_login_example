from fastapi import FastAPI
from login import user_login_router
from db import Base, engine

app = FastAPI()
app.include_router(user_login_router)
Base.metadata.create_all(bind=engine)


@app.get("/")
async def root():
    return {"message": "Please login to use API"}

