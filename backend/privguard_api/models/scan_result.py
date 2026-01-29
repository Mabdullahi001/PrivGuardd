from __future__ import annotations
from datetime import datetime
from sqlalchemy import String, DateTime, Integer, ForeignKey, Float, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from privguard_api.db.session import Base

class ScanResult(Base):
    __tablename__ = "scan_results"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id", ondelete="CASCADE"), index=True)

    gmail_message_id: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    thread_id: Mapped[str] = mapped_column(String(128), nullable=True)
    subject: Mapped[str] = mapped_column(String(998), nullable=True)
    sender: Mapped[str] = mapped_column(String(998), nullable=True)
    date: Mapped[str] = mapped_column(String(256), nullable=True)

    threat_level: Mapped[str] = mapped_column(String(32), nullable=False)
    risk_score: Mapped[float] = mapped_column(Float, nullable=False)

    reasons_json: Mapped[str] = mapped_column(Text, nullable=False)
    recommendations_json: Mapped[str] = mapped_column(Text, nullable=False)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)

    user = relationship("User", back_populates="scan_results")
