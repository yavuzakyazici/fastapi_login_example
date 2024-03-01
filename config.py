
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