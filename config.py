import os
from dotenv import load_dotenv

load_dotenv()

# Network Settings
INTERFACE = os.getenv("SNIFF_INTERFACE", "Wi-Fi") # default for local dev
PCAP_FILTER = "udp port 53"

# Paths
MODEL_PATH = "models/trained_model.pkl"

# Database connection
# e.g., postgresql://user:password@endpoint.neon.tech/dbname?sslmode=require
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///detections.db") # Fallback to local sqlite for immediate running
