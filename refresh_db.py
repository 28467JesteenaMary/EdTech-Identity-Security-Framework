from app import app
from models import db

with app.app_context():
    print("Synching Aether-Chasm Database Schema...")
    # This will create tables that don't exist.
    # Note: If columns were added to existing tables, create_all() won't add them.
    # We'll drop and recreate since this is development.
    db.drop_all()
    db.create_all()
    print("Schema Synchronized Successfully.")
