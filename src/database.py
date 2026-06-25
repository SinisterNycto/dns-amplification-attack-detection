from sqlalchemy import create_engine, Column, Integer, Float, String, DateTime
from sqlalchemy.orm import declarative_base, sessionmaker
import sys
import os
import datetime

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import DATABASE_URL

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class DetectionLog(Base):
    __tablename__ = "detection_logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.datetime.now)
    dst_ip = Column(String, index=True)
    queries_per_sec = Column(Integer)
    responses_per_sec = Column(Integer)
    response_to_query_ratio = Column(Float)
    avg_response_size = Column(Float)
    confidence = Column(Float)
    label = Column(String)  # "NORMAL" or "ATTACK"

# Create tables
Base.metadata.create_all(bind=engine)

def save_detection(dst_ip, qps, rps, ratio, avg_size, conf, label):
    db = SessionLocal()
    try:
        log = DetectionLog(
            dst_ip=dst_ip,
            queries_per_sec=qps,
            responses_per_sec=rps,
            response_to_query_ratio=ratio,
            avg_response_size=avg_size,
            confidence=conf,
            label=label
        )
        db.add(log)
        db.commit()
    except Exception as e:
        print(f"Database error: {e}")
    finally:
        db.close()
