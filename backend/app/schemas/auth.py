from pydantic import BaseModel
from typing import Optional

class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    role: str
    username: str
    org_name: Optional[str] = None

class TokenPayload(BaseModel):
    sub: Optional[str] = None
    type: Optional[str] = None
