"""
User Model
Represents platform analysts, administrators, and automated system service accounts.
"""

from sqlalchemy import Boolean, Column, String
from app.models.base import BaseModel


class User(BaseModel):
    """User account model for platform authentication and authorization."""

    __tablename__ = "users"

    email = Column(String(255), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    full_name = Column(String(255), nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)
    is_superuser = Column(Boolean, default=False, nullable=False)
    role = Column(String(50), default="analyst", nullable=False)

    def __repr__(self) -> str:
        return f"<User(id={self.id}, email='{self.email}', role='{self.role}')>"
