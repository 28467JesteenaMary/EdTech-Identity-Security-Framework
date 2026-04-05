import pyotp
import qrcode
import base64
import io
import random
import string
import bcrypt
from datetime import datetime, timedelta
from models import db, IPBlacklist

def generate_totp_secret():
    """Returns a random Base32 string (16 chars) for pyotp."""
    return pyotp.random_base32()

def get_totp_uri(email, secret, issuer="EdTechApp"):
    """Returns the provisioning URI."""
    return pyotp.totp.TOTP(secret).provisioning_uri(name=email, issuer_name=issuer)

def generate_qr_base64(uri):
    """Creates QR code PNG in memory, returns Base64 string."""
    qr = qrcode.QRCode(version=1, box_size=10, border=4)
    qr.add_data(uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    
    buffered = io.BytesIO()
    img.save(buffered, format="PNG")
    return base64.b64encode(buffered.getvalue()).decode('utf-8')

def verify_totp(secret, user_code):
    """Verifies TOTP taking clock drift into account."""
    if not secret: return False
    totp = pyotp.TOTP(secret)
    return totp.verify(user_code, valid_window=5)

def generate_backup_codes(count=10, digits=8):
    """Generate plain string list of digits."""
    codes = []
    for _ in range(count):
        codes.append(''.join(random.choices(string.digits, k=digits)))
    return codes

def hash_string(text):
    """Hashes a string using bcrypt."""
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(text.encode('utf-8'), salt).decode('utf-8')

def check_hash(text, hash_str):
    """Verifies a hash."""
    return bcrypt.checkpw(text.encode('utf-8'), hash_str.encode('utf-8'))

def check_ip_blacklist(ip):
    """Returns (blocked: bool, remaining_seconds: int)"""
    record = IPBlacklist.query.filter_by(ip_address=ip).first()
    if record and record.blocked_until and record.blocked_until > datetime.utcnow():
        delta = record.blocked_until - datetime.utcnow()
        return True, int(delta.total_seconds())
    return False, 0

def record_ip_failure(ip):
    """Increments failed attempts; flags IP if > 5"""
    record = IPBlacklist.query.filter_by(ip_address=ip).first()
    if not record:
        record = IPBlacklist(ip_address=ip, failed_attempts=1)
        db.session.add(record)
    else:
        record.failed_attempts += 1
    
    if record.failed_attempts >= 5:
        record.blocked_until = datetime.utcnow() + timedelta(minutes=15)
        
    db.session.commit()

def clear_ip_failures(ip):
    record = IPBlacklist.query.filter_by(ip_address=ip).first()
    if record:
        db.session.delete(record)
        db.session.commit()
