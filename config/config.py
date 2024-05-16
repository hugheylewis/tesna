import os
from dotenv import load_dotenv, find_dotenv
from dataclasses import dataclass

load_dotenv(find_dotenv())  # finds the .env file in the local config directory


@dataclass(frozen=True)  # makes the API keys immutable
class APIkeys:
    access_key: str = os.getenv('access_key')
    secret_key: str = os.getenv('secret_key')
