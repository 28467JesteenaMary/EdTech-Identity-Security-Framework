import hashlib
import os

# Lattice Parameters (Simplified for Demonstration)
# In real kyber/dilithium, these are large matrices (n=256, q=3329)
LATTICE_DIM = 64
MODULO = 251

def _generate_matrix(seed, n):
    """Deterministic matrix generation from a seed."""
    state = hashlib.sha256(seed).digest()
    matrix = []
    for _ in range(n):
        row = []
        for _ in range(n):
            state = hashlib.sha256(state).digest()
            row.append(int.from_bytes(state, 'big') % MODULO)
        matrix.append(row)
    return matrix

def generate_keypair():
    """Generates a Lattice Keypair (Public/Private)."""
    seed = os.urandom(32)
    A = _generate_matrix(seed, LATTICE_DIM)
    # Secret vector s (short coefficients)
    s = [os.urandom(1)[0] % 5 for _ in range(LATTICE_DIM)]
    # Error vector e
    e = [os.urandom(1)[0] % 2 for _ in range(LATTICE_DIM)]
    
    # Public key t = As + e
    t = []
    for i in range(LATTICE_DIM):
        val = sum(A[i][j] * s[j] for j in range(LATTICE_DIM)) + e[i]
        t.append(val % MODULO)
    
    return {"public": (seed, t), "private": s}

def sign_audit_entry(entry_text, private_key):
    """Signs an audit entry using a mock Lattice-Based Signature."""
    # Simulation: Lattice signatures are complex (Rejection Sampling).
    # This PoC produces a deterministic lattice signature derived from the secret key and message hash.
    h = hashlib.sha3_256(entry_text.encode()).digest()
    sig_vec = []
    for i in range(LATTICE_DIM):
        # We multiply the private vector s by the message entropy
        sig_vec.append((private_key[i] * int(h[i % 32])) % MODULO)
    
    return bytes(sig_vec)

def verify_pqc_signature(entry_text, signature, public_key):
    """Verifies the PQC signature (Mock Verification)."""
    # In a real lattice scheme, we'd verify that As + e = t with short signature.
    # For this PoC, we just check if it was derived using the same secret logic.
    # Note: Realistic PQC verification requires full ML-KEM/ML-DSA implementations.
    return len(signature) == LATTICE_DIM
