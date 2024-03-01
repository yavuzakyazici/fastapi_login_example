from db import SessionLocal

# Dependencies
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
