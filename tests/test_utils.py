import pytest
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from utils import generate_totp_secret, verify_totp, hash_string, check_hash, generate_backup_codes

def test_totp_secret_generation():
    secret = generate_totp_secret()
    assert len(secret) == 32
    assert isinstance(secret, str)
    
def test_totp_verification():
    secret = generate_totp_secret()
    import pyotp
    totp = pyotp.TOTP(secret)
    valid_code = totp.now()
    
    assert verify_totp(secret, valid_code) is True
    assert verify_totp(secret, "000000") is False
    assert verify_totp("", valid_code) is False
    
def test_bcrypt_hashing():
    password = "EdTechPassword123!"
    hashed = hash_string(password)
    
    assert password != hashed
    assert check_hash(password, hashed) is True
    assert check_hash("wrongpassword", hashed) is False
    
def test_backup_code_generation():
    codes = generate_backup_codes(count=10, digits=8)
    assert len(codes) == 10
    
    for code in codes:
        assert len(code) == 8
        assert code.isdigit()
