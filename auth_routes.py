import os
from datetime import datetime, timedelta
from flask import Blueprint, request, redirect, url_for, flash, session, render_template
from flask_login import login_user, logout_user, login_required, current_user
from authlib.integrations.flask_client import OAuth
from models import db, User, BackupCode, AllowedStudentId, AllowedTeacherEmail, AuditLog
import utils
import json
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import base64

auth_bp = Blueprint('auth', __name__)

oauth = OAuth()
oauth.register(
    name='google',
    client_id=os.getenv('GOOGLE_CLIENT_ID', 'placeholder_client_id'),
    client_secret=os.getenv('GOOGLE_CLIENT_SECRET', 'placeholder_secret'),
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'},
)

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('profile.dashboard'))
        
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        user = User.query.filter_by(email=email).first()
        
        # Check Account Lockout
        if user and user.locked_until and user.locked_until > datetime.utcnow():
            delta = int((user.locked_until - datetime.utcnow()).total_seconds() / 60)
            flash(f'Account locked due to multiple failed attempts. Try again in {delta} minutes.', 'danger')
            return render_template('login.html')
            
        if user and utils.check_hash(password, user.password_hash):
            user.failed_attempts = 0
            user.locked_until = None
            db.session.commit()
            
            if user.is_2fa_required:
                session['pending_2fa_user_id'] = user.id
                return redirect(url_for('auth.verify_2fa'))
            elif user.public_hardware_key:
                session['pending_sentinel_user_id'] = user.id
                return redirect(url_for('auth.verify_sentinel_page'))
            else:
                user.login_count += 1
                db.session.commit()
                login_user(user)
                return redirect(url_for('profile.dashboard'))
        else:
            if user:
                user.failed_attempts += 1
                if user.failed_attempts >= 5:
                    user.locked_until = datetime.utcnow() + timedelta(minutes=15)
                db.session.commit()
            flash('Invalid email or password.', 'danger')
            
    return render_template('login.html')

@auth_bp.route('/login/google')
def google_login():
    redirect_uri = url_for('auth.google_callback', _external=True)
    return oauth.google.authorize_redirect(redirect_uri)

@auth_bp.route('/login/google/callback')
def google_callback():
    token = oauth.google.authorize_access_token()
    user_info = token.get('userinfo')
    
    if not user_info:
        flash('Failed to sign in with Google.', 'danger')
        return redirect(url_for('auth.login'))
        
    email = user_info['email']
    google_id = user_info['sub']
    
    user = User.query.filter_by(email=email).first()
    
    if not user:
        # Check if the email exists in the Teacher Whitelist
        if AllowedTeacherEmail.query.filter_by(email=email).first():
            user = User(email=email, google_id=google_id, password_hash="OAUTH", role='teacher', login_count=0, is_2fa_required=True)
            db.session.add(user)
            db.session.commit()
            session['pending_setup_user_id'] = user.id
            flash('Instructor recognized via Google. Please configure 2FA.', 'info')
            return redirect(url_for('auth.setup_2fa'))
        else:
            # If not a whitelisted teacher, and no Campus ID is provided to Google, block them
            flash('Unrecognized Email. If you are a Student, please register manually with your Campus ID first to bind it.', 'danger')
            # Record unauthorized SSO probe against IP Blacklist
            ip = request.remote_addr
            utils.record_ip_failure(ip)
            return redirect(url_for('auth.login'))
        
    if user.is_2fa_required:
        session['pending_2fa_user_id'] = user.id
        return redirect(url_for('auth.verify_2fa'))
    elif user.public_hardware_key:
        session['pending_sentinel_user_id'] = user.id
        return redirect(url_for('auth.verify_sentinel_page'))
    else:
        user.login_count += 1
        db.session.commit()
        login_user(user)
        return redirect(url_for('profile.dashboard'))

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        ip = request.remote_addr
        blocked, remaining = utils.check_ip_blacklist(ip)
        if blocked:
            flash(f'Your IP is temporarily blocked due to multiple failed registrations. Try again in {remaining//60} mins.', 'danger')
            return redirect(url_for('auth.register'))
            
        email = request.form.get('email')
        password = request.form.get('password')
        role = request.form.get('role') # 'student' or 'teacher'
        identifier = request.form.get('identifier') # Campus ID or Teacher Email repeated/explicit
        
        # Validate based on role
        if role == 'student':
            if not AllowedStudentId.query.filter_by(campus_id=identifier).first():
                utils.record_ip_failure(ip)
                flash('Invalid Campus ID. Registration denied.', 'danger')
                return redirect(url_for('auth.register'))
        elif role == 'teacher':
            if not AllowedTeacherEmail.query.filter_by(email=email).first():
                utils.record_ip_failure(ip)
                flash('Email is not whitelisted for teachers.', 'danger')
                return redirect(url_for('auth.register'))
        else:
            flash('Invalid role selected.', 'danger')
            return redirect(url_for('auth.register'))
            
        if User.query.filter_by(email=email).first():
            flash('Email is already registered.', 'danger')
            return redirect(url_for('auth.register'))
            
        # Clean IP
        utils.clear_ip_failures(ip)
        
        new_user = User(email=email, password_hash=utils.hash_string(password), role=role, is_2fa_required=True)
        db.session.add(new_user)
        db.session.commit()
        
        session['pending_setup_user_id'] = new_user.id
        flash('Registration successful. You must now configure Two-Factor Authentication.', 'info')
        return redirect(url_for('auth.setup_2fa'))
        
    return render_template('register.html')

@auth_bp.route('/setup-2fa', methods=['GET', 'POST'])
def setup_2fa():
    user_id = session.get('pending_setup_user_id')
    if not user_id and current_user.is_authenticated:
        user_id = current_user.id 
        
    if not user_id:
        return redirect(url_for('auth.login'))
        
    user = User.query.get(user_id)
    
    if request.method == 'POST':
        totp_code = request.form.get('totp_code', '').strip()
        secret = session.get('temp_totp_secret')
        
        # DEBUG output to server terminal to help sync
        if secret:
            import pyotp
            expected = pyotp.TOTP(secret).now()
            print(f"DEBUG - User entered: {totp_code} | Expected: {expected} | Secret: {secret}")

        if utils.verify_totp(secret, totp_code):
            user.totp_secret = secret
            user.is_2fa_required = True
            
            # Generate backup codes
            backup_codes_plain = utils.generate_backup_codes()
            for bc in user.backup_codes:
                db.session.delete(bc)
                
            for code in backup_codes_plain:
                db.session.add(BackupCode(user_id=user.id, code_hash=utils.hash_string(code)))
                
            if 'pending_setup_user_id' in session:
                user.login_count += 1
                login_user(user)
                session.pop('pending_setup_user_id', None)
                
            db.session.commit()
            session.pop('temp_totp_secret', None)
            session['new_backup_codes'] = backup_codes_plain
            
            return redirect(url_for('profile.backup_codes_display'))
        else:
            flash('Invalid TOTP code. Please ensure your device matches the QR code.', 'danger')
            
    if 'temp_totp_secret' not in session:
        secret = utils.generate_totp_secret()
        session['temp_totp_secret'] = secret
    else:
        secret = session['temp_totp_secret']
        
    uri = utils.get_totp_uri(user.email, secret)
    qr_b64 = utils.generate_qr_base64(uri)
    
    return render_template('setup_2fa.html', secret=secret, qr_b64=qr_b64)

@auth_bp.route('/verify-2fa', methods=['GET', 'POST'])
def verify_2fa():
    if 'pending_2fa_user_id' not in session:
        return redirect(url_for('auth.login'))
        
    user = User.query.get(session['pending_2fa_user_id'])
    
    if user.locked_2fa_until and user.locked_2fa_until > datetime.utcnow():
        flash('2FA locked due to consecutive failures. Please try again in 15 minutes.', 'danger')
        return render_template('verify_2fa.html')
        
    if request.method == 'POST':
        totp_code = request.form.get('totp_code', '').strip()
        backup_code = request.form.get('backup_code', '').strip()
        
        success = False
        if totp_code and utils.verify_totp(user.totp_secret, totp_code):
            success = True
        elif backup_code:
            for bc in user.backup_codes:
                if not bc.used and utils.check_hash(backup_code, bc.code_hash):
                    bc.used = True
                    success = True
                    break
                    
        if success:
            user.failed_2fa_attempts = 0
            user.locked_2fa_until = None
            user.login_count += 1
            db.session.commit()
            
            session.pop('pending_2fa_user_id', None)
            login_user(user)
            return redirect(url_for('profile.dashboard'))
        else:
            user.failed_2fa_attempts += 1
            if user.failed_2fa_attempts >= 5:
                user.locked_2fa_until = datetime.utcnow() + timedelta(minutes=15)
            db.session.commit()
            flash('Invalid 2FA code.', 'danger')
            
    return render_template('verify_2fa.html')

@auth_bp.route('/register-sentinel', methods=['POST'])
@login_required
def register_sentinel():
    """Binds a hardware public key to the user account."""
    public_key_pem = request.json.get('public_key')
    node_id = request.json.get('node_id')
    
    if not public_key_pem or not node_id:
        return json.dumps({'status': 'error', 'message': 'Missing data'}), 400
        
    current_user.public_hardware_key = public_key_pem
    current_user.network_node_id = node_id
    db.session.commit()
    
    # Audit Log with PQC Simulation
    from utils import lattice_crypto
    log_entry = f"SENTINEL_LINK: {node_id}"
    pqc_sig = lattice_crypto.sign_audit_entry(log_entry, lattice_crypto.generate_keypair()['private'])
    db.session.add(AuditLog(action="SENTINEL_BIND", user_id=current_user.id, details=log_entry, pqc_signature=pqc_sig))
    db.session.commit()
    
    return json.dumps({'status': 'ok', 'message': 'Sentinel Link Established'})

@auth_bp.route('/verify-sentinel-challenge')
def verify_sentinel_challenge():
    """Provides a nonce for the hardware key to sign."""
    user_id = session.get('pending_sentinel_user_id') or (current_user.id if current_user.is_authenticated else None)
    if not user_id: return "Unauthorized", 401
    
    nonce = os.urandom(32).hex()
    session['sentinel_nonce'] = nonce
    return json.dumps({'nonce': nonce})

@auth_bp.route('/verify-sentinel', methods=['POST'])
def verify_sentinel():
    """Verifies the signed nonce using the stored RSA public key."""
    user_id = session.get('pending_sentinel_user_id')
    if not user_id: return json.dumps({'status': 'error'}), 401
    
    user = User.query.get(user_id)
    signed_nonce_b64 = request.json.get('signature')
    nonce = session.get('sentinel_nonce')
    
    if not signed_nonce_b64 or not nonce:
        return json.dumps({'status': 'error', 'message': 'Missing signature/nonce'}), 400
        
    try:
        # Import the public key
        key = RSA.import_key(user.public_hardware_key)
        h = SHA256.new(nonce.encode())
        signature = base64.b64decode(signed_nonce_b64)
        
        # Verify (Simulation: Using PyCryptodome for RSA verification)
        pkcs1_15.new(key).verify(h, signature)
        
        # Success Logic
        user.login_count += 1
        db.session.commit()
        session.pop('pending_sentinel_user_id', None)
        session.pop('sentinel_nonce', None)
        login_user(user)
        return json.dumps({'status': 'ok'})
    except (ValueError, TypeError):
        return json.dumps({'status': 'error', 'message': 'Hardware Handshake Failed'}), 401

@auth_bp.route('/sentinel-challenge-page')
def verify_sentinel_page():
    if 'pending_sentinel_user_id' not in session:
        return redirect(url_for('auth.login'))
    return render_template('verify_sentinel.html')

@auth_bp.route('/recover-account', methods=['GET', 'POST'])
def recover_account():
    """Recovers 2FA secret using decentralized shards (Shamir's)."""
    if request.method == 'POST':
        email = request.form.get('email')
        shard1 = request.json.get('shard1') # Expects [index, value]
        shard2 = request.json.get('shard2')
        
        user = User.query.filter_by(email=email).first()
        if not user or not user.recovery_shards:
            return json.dumps({'status': 'error', 'message': 'Recovery not configured.'}), 404
            
        try:
            from utils import sss
            # Reconstruct from provided shards
            shares = [tuple(shard1), tuple(shard2)]
            secret = sss.shards_to_secret(shares)
            
            # Verify reconstructed secret (it should match their TOTP secret)
            if secret == user.totp_secret:
                session['pending_2fa_user_id'] = user.id
                flash('Recovery Shard Handshake Successful. Secret Restored.', 'success')
                return json.dumps({'status': 'ok'})
            else:
                return json.dumps({'status': 'error', 'message': 'Shard Reconstruction Failed.'}), 401
        except Exception as e:
            return json.dumps({'status': 'error', 'message': f"Quantum Reconstruction Error: {str(e)}"}), 400
            
    return render_template('recover_account.html')

@auth_bp.route('/logout')
@login_required
def logout():
    logout_user()
    session.pop('pending_2fa_user_id', None)
    session.pop('pending_sentinel_user_id', None)
    flash('Logged out successfully.', 'info')
    return redirect(url_for('auth.login'))
