"""Failed login attempts for lockout and brute-force detection."""

from datetime import datetime

from sqlalchemy import Integer, String, DateTime
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql import func

from app.database import Base


class FailedLogin(Base):
    __tablename__ = "failed_logins"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    ip_address: Mapped[str] = mapped_column(String(45), nullable=True)
    attempted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    locked_until: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)
