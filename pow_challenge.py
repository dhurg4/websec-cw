import hashlib
import hmac
import json
import os
import secrets
import threading
import time

CHALLENGE_EXPIRATION = 60
DIFFICULTY = 15 # leading zero bits (currently fixed, will be changed to dynamic)
MAX_DIFFICULTY = 30 # hard cap to prevent legitimate users from facing DoS

_secretkey = os.environ.get("HMAC_KEY")
_SECRET = _secretkey.encode() if _secretkey else secrets.token_bytes(32)

_SIGNED_FIELDS = ("id", "salt", "expires", "difficulty", "client")

# signing
def _sign(fields: dict) -> str:
    """HMAC-SHA256 over JSON encoding of signed fields."""
    canonical = json.dumps(fields, sort_keys=True, separators=(",", ":"))
    return hmac.new(_SECRET, canonical.encode(), hashlib.sha256).hexdigest()

# hashing
def compute_hash(salt: str, nonce: int) -> bytes:
    return hashlib.sha256(f"{salt}{nonce}".encode()).digest()
 
 
def leading_zero_bits(digest: bytes) -> int:
    value = int.from_bytes(digest, "big")
    return len(digest) * 8 - value.bit_length()

# replay cache
_used: dict = {}
_lock = threading.Lock()

def _expired(current: float) -> None:
    for cid in [c for c, exp in _used.items() if exp < current]:
        del _used[cid]

def _is_used(challenge_id: str) -> bool:
    with _lock:
        _expired(time.time())
        return challenge_id in _used

def _mark_used(challenge_id: str, expires: int) -> bool:
    """Atomic check and mark. Returns False id was already used."""
    with _lock:
        _expired(time.time())
        if challenge_id in _used:
            return False
        _used[challenge_id] = expires
        return True

def generate_challenge(client_id: str,
                     difficulty: int = DIFFICULTY,
                     ttl: int = CHALLENGE_EXPIRATION) -> dict:
    """Create a signed challenge bound to one client."""
    difficulty = max(1, min(difficulty, MAX_DIFFICULTY))
    body = {
        "id": secrets.token_hex(16),
        "salt": secrets.token_hex(16),
        "expires": int(time.time()) + ttl,
        "difficulty": difficulty,
        "client": client_id,
    }
    body["signature"] = _sign(body)
    return body

def verify_solution(challenge: dict, nonce: int, client_id: str):

    # ensures inputs are formatted correctly
    try:
        body = {k: challenge[k] for k in _SIGNED_FIELDS}
        signature = str(challenge["signature"])
    except (KeyError, TypeError):
        return False, "malformed challenge"
    if not isinstance(nonce, int) or isinstance(nonce, bool) or nonce < 0:
        return False, "malformed nonce"

    # signature
    if not hmac.compare_digest(_sign(body), signature):
        return False, "invalid signature"
    
    #expiration
    if time.time() > body["expires"]:
        return False, "challenge expired"
 
    # bound to the client it was issued to
    if body["client"] != client_id:
        return False, "challenge issued to a different client"
 
    # replay (cheap pre-check)
    if _is_used(body["id"]):
        return False, "challenge already used"
 
    # the actual proof of work
    digest = compute_hash(body["salt"], nonce)
    if leading_zero_bits(digest) < body["difficulty"]:
        return False, "insufficient work"
 
    # atomic mark as used (handles concurrent submissions)
    if not _mark_used(body["id"], body["expires"]):
        return False, "challenge already used"
 
    return True, "ok"

def solve(challenge: dict) -> int:
    nonce = 0
    while leading_zero_bits(compute_hash(challenge["salt"], nonce)) < challenge["difficulty"]:
        nonce += 1
    return nonce

# test

if __name__ == "__main__":
    client = "127.0.0.1"
 
    ch = generate_challenge(client)
    t0 = time.time()
    nonce = solve(ch)
    print(f"solved difficulty {ch['difficulty']} in {time.time() - t0:.2f}s (nonce={nonce})")
 
    print("valid solution      :", verify_solution(ch, nonce, client))
    print("replayed solution   :", verify_solution(ch, nonce, client))
 
    ch2 = generate_challenge(client)
    tampered = dict(ch2, difficulty=1)
    print("tampered difficulty :", verify_solution(tampered, 0, client))
 
    expired = generate_challenge(client, ttl=-1)
    print("expired challenge   :", verify_solution(expired, 0, client))
 
    ch3 = generate_challenge(client)
    print("wrong client        :", verify_solution(ch3, solve(ch3), "10.0.0.9"))
 
    ch4 = generate_challenge(client)
    print("bad nonce           :", verify_solution(ch4, 0, client))
 
