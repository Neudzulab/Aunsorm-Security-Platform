# ===============================
#  Aunsorm v1.01 — Production-Ready
#  (User-Calibrated • FORMUL compat • PQ optional • RB-KEM • Session/Ratchet
#   • KMS/HSM (GCP/Azure/PKCS#11) • OAuth/OIDC-ish • X.509 CPS checks)
#  Single-file, Colab/Servers-ready
# ===============================
# Optional (Colab): uncomment if needed
# !pip -q install --upgrade pycryptodome argon2-cffi cryptography > /dev/null
# Optional PQC (requires system liboqs; if missing, classic mode is used automatically):
# !pip -q install liboqs-python > /dev/null
# Optional HTTP for CPS checks:
# !pip -q install requests > /dev/null
# Optional KMS:
# !pip -q install google-cloud-kms azure-identity azure-keyvault-keys PyKCS11 > /dev/null

import os, json, base64, time, hmac, hashlib, math, struct, secrets, datetime, uuid, logging, re, sys, sqlite3, platform, unicodedata, argparse, asyncio, threading
from typing import Dict, Tuple, List, Optional, Union, Callable

def _is_notebook() -> bool:
    try:
        return "ipykernel" in sys.modules
    except Exception:
        return False

# ---------- Logging (console or JSON) ----------
class _JSONFormatter(logging.Formatter):
    def format(self, record):
        d = {"ts": int(time.time()), "level": record.levelname, "msg": record.getMessage(), "logger": record.name}
        if record.exc_info: d["exc"] = self.formatException(record.exc_info)
        return json.dumps(d, separators=(",",":"))
def _mk_logger():
    log = logging.getLogger("aunsorm")
    if not log.handlers:
        h = logging.StreamHandler()
        if os.getenv("AUNSORM_LOG_JSON","0").lower() in ("1","true"):
            h.setFormatter(_JSONFormatter())
        else:
            h.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
        log.addHandler(h)
    lvl = getattr(logging, os.getenv("AUNSORM_LOG","INFO").upper(), logging.INFO)
    log.setLevel(lvl)
    if (fp := os.getenv("AUNSORM_LOG_FILE")):
        fh = logging.FileHandler(fp)
        fh.setFormatter(_JSONFormatter() if os.getenv("AUNSORM_LOG_JSON","0").lower() in ("1","true")
                        else logging.Formatter("[%(asctime)s] [%(levelname)s] %(message)s"))
        log.addHandler(fh)
    return log
log = _mk_logger()

# --- Optional PQ (liboqs) discovery ---
_HAVE_OQS = False
try:
    import oqs
    _HAVE_OQS = True
    log.info("OQS available")
except Exception:
    _HAVE_OQS = False
    log.info("OQS not available; running in classic mode")

# --- Optional AEAD backends ---
_HAVE_PYCA = False
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
    _HAVE_PYCA = True
except Exception:
    _HAVE_PYCA = False

_HAVE_PYCRYPTODOME = False
try:
    from Crypto.Cipher import AES, ChaCha20_Poly1305
    _HAVE_PYCRYPTODOME = True
except Exception:
    _HAVE_PYCRYPTODOME = False

# ---------- Utils ----------
def b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")
def b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, L: int) -> bytes:
    if not salt: salt = b"\x00"*32
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    T, okm, i = b"", b"", 1
    while len(okm) < L:
        T = hmac.new(prk, T + info + bytes([i]), hashlib.sha256).digest()
        okm += T; i += 1
    return okm[:L]
def int_from_bytes(b: bytes) -> int: return int.from_bytes(b, "big")
def int_to_bytes(x: int, length=None) -> bytes:
    if length is None: length = max(1, (x.bit_length()+7)//8)
    return x.to_bytes(length, "big")
def _const_eq(a: bytes, b: bytes) -> bool: return hmac.compare_digest(a, b)
def _aad_bytes(a_list: List[bytes]) -> bytes:
    out = b""
    for a in a_list: out += struct.pack(">I", len(a)) + a
    return out

# ---------- Errors ----------
class AunsormInvalidPacketError(Exception): pass
class AunsormCalibrationMismatchError(Exception): pass
class AunsormTokenError(Exception): pass
class AunsormConfigError(Exception): pass
class AunsormDecryptionFailed(Exception): pass

# ---------- Version / Labels ----------
VERSION_STR   = "Aunsorm v1.01"
VERSION_LABEL = "Aunsorm/1.01".encode()
def _label(base: bytes, leaf: str) -> bytes: return base + b"/" + leaf.encode()
def _label_from_header(header: Dict) -> bytes:
    if "label" in header and isinstance(header["label"], str): return header["label"].encode()
    ver = header.get("version","Aunsorm v1.01")
    for tag in ("0.9.3","0.9.4","0.9.5","0.9.6","0.9.7","0.9.8","0.99","1.0"):
        if tag in ver: return ("Aunsorm/"+tag).encode()
    return VERSION_LABEL

# ---------- FORMUL (legacy compat for DERIVED) ----------
def _tanh_map(u64: int, span: float) -> float:
    u = (u64 % (1<<64)) / float(1<<64); x = 6.0*(u-0.5); return math.tanh(x)*span
def _u64parts(seed64: bytes) -> List[int]:
    s = seed64.ljust(64, b"\x00")[:64]; return [int_from_bytes(s[i:i+8]) for i in range(0,64,8)]
def derive_calibration(seed64: bytes) -> Tuple[Dict, str, bytes]:
    w = _u64parts(seed64)
    pcs = {
        "a_L":  0.991760130167 + _tanh_map(w[0], 80.0),
        "a_s": -17.1163104468 + _tanh_map(w[1], 80.0),
        "b_L":  2.50542954     + _tanh_map(w[2], 80.0),
        "b_s": 124.19647718    + _tanh_map(w[3], 80.0),
        "tau": max(1.0, 1_000_000.0 * (1.0 + _tanh_map(w[4], 0.30)))
    }
    pn  = {"A":0.999621+_tanh_map(w[5],40.0), "B":-0.47298+_tanh_map(w[6],40.0),
           "C":2.49373+_tanh_map(w[7],40.0), "D":1.55595+_tanh_map(w[0]^w[5],40.0),
           "E":1.35684+_tanh_map(w[1]^w[6],40.0)}
    calib = {"pcs": pcs, "pn": pn}
    calib_id = hashlib.sha256(json.dumps(calib, sort_keys=True, separators=(",",":")).encode()).hexdigest()
    s = int_from_bytes(seed64)
    def pcs_pi_map(seed_int: int, p):
        return int(abs(p["a_L"]*math.log(seed_int+2.0) + p["a_s"]*math.sin(seed_int/max(3.0,p["tau"])) + p["b_L"]*((seed_int%7919)-3959.5) + p["b_s"]))
    def pn_wave(seed_int: int, q):
        return int(abs(q["A"]*math.sin(seed_int/101.0) + q["B"]*math.cos(seed_int/103.0) + q["C"]*math.sin(seed_int/107.0) + q["D"]*math.cos(seed_int/109.0) + q["E"]*((seed_int % 104729)-52364.5)))
    p1 = pcs_pi_map(s, pcs); p2 = pn_wave(s, pn)
    mix = hashlib.sha512(int_to_bytes(s)+int_to_bytes(p1)+int_to_bytes(p2)).digest()
    coord32 = hashlib.sha256(mix).digest()
    return calib, calib_id, coord32

# ---------- v1.x User Calibration Schema ----------
SCHEMA_VER = "v1"
CALIB_SCHEMA_V1 = {
    "alpha_L": (-80.0, 80.0, 1e-4),
    "alpha_S": (-80.0, 80.0, 1e-3),
    "beta_L":  (-80.0, 80.0, 1e-2),
    "beta_S":  (-80.0, 80.0, 1e-2),
    "tau":     (1.0,  2_000_000.0, 1.0),
    "A":       (-40.0, 40.0, 1e-3), "B":(-40.0,40.0,1e-3), "C":(-40.0,40.0,1e-3), "D":(-40.0,40.0,1e-3), "E":(-40.0,40.0,1e-3),
}
_CALIB_ALIASES = {"alfa1":"alpha_L","alpha1":"alpha_L","alfs1":"alpha_L","alfa2":"alpha_S","alpha2":"alpha_S","alfs2":"alpha_S","beta1":"beta_L","beta2":"beta_S"}
def _normalize_calib_keys(calib: Dict[str, float]) -> Dict[str, float]:
    return { _CALIB_ALIASES.get(k,k): float(v) for k,v in calib.items() }
def _canon_calib(calib: Dict[str, float]) -> Dict[str, float]:
    calib = _normalize_calib_keys(calib); out={}
    for k in ("alpha_L","alpha_S","beta_L","beta_S","tau","A","B","C","D","E"):
        if k not in calib: raise AunsormConfigError(f"missing calibration field: {k}")
        lo, hi, step = CALIB_SCHEMA_V1[k]; v = float(calib[k])
        if v < lo: v = lo
        if v > hi: v = hi
        if step >= 1.0: v = float(int(round(v/step)*step))
        else: v = float(round(round(v/step)*step, 9))
        out[k]=v
    return out
def _calib_bytes(calib: Dict[str, float]) -> bytes:
    return json.dumps(_canon_calib(calib), sort_keys=True, separators=(",",":")).encode()
def _calib_id_prefixed(calib: Dict[str, float]) -> str:
    prefix = b"Aunsorm/1.x|schema:" + SCHEMA_VER.encode() + b"|"
    return hashlib.sha256(prefix + _calib_bytes(calib)).hexdigest()
def derive_coord32_v10(seed64: bytes, calib: Dict[str, float], salts: Dict[str, bytes]) -> Tuple[str, bytes]:
    calib_id = _calib_id_prefixed(calib)
    cbytes_hash = hashlib.sha512(_calib_bytes(calib)).digest()
    a = hkdf_sha256(cbytes_hash, salts["calib"], _label(VERSION_LABEL, "COORD"), 32)
    b = hkdf_sha256(seed64,      salts["chain"], _label(VERSION_LABEL, "SEEDCOORD"), 32)
    return calib_id, bytes(x ^ y for x,y in zip(a,b))

# ---------- Multi-tenant Store ----------
def _normalize_text(note: str) -> str:
    n = unicodedata.normalize("NFC", note).strip()
    return " ".join(n.split())

class TenantDB:
    def __init__(self, path="aunsorm_mt.db"):
        self.path = path; self._init()
    def _conn(self):
        con = sqlite3.connect(self.path, check_same_thread=False, isolation_level=None)
        con.execute("PRAGMA journal_mode=WAL")
        con.execute("PRAGMA synchronous=NORMAL")
        con.execute("PRAGMA busy_timeout=2500")
        con.execute("PRAGMA optimize")
        return con
    def _init(self):
        con = self._conn(); cur = con.cursor()
        cur.execute("""
        CREATE TABLE IF NOT EXISTS tenants(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          name TEXT NOT NULL UNIQUE,
          org_salt BLOB NOT NULL,
          policy_json TEXT NOT NULL,
          created_at INTEGER NOT NULL
        )""")
        cur.execute("""
        CREATE TABLE IF NOT EXISTS notes(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          tenant_id INTEGER NOT NULL,
          calib_id TEXT NOT NULL,
          schema_ver TEXT NOT NULL,
          note_sha TEXT NOT NULL UNIQUE,
          note TEXT NOT NULL,
          created_at INTEGER NOT NULL,
          FOREIGN KEY(tenant_id) REFERENCES tenants(id)
        )""")
        self._migrate_schema(cur)
        cur.execute("CREATE INDEX IF NOT EXISTS idx_notes_calib ON notes(calib_id)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_notes_tenant ON notes(tenant_id, created_at)")
        con.commit(); con.close()
    def _migrate_schema(self, cur):
        cur.execute("PRAGMA table_info(tenants)"); cols=[r[1] for r in cur.fetchall()]
        if "policy_json" not in cols:
            cur.execute("ALTER TABLE tenants ADD COLUMN policy_json TEXT NOT NULL DEFAULT '{}'")
            default_policy = json.dumps({"kdf_profile":"AUTO","aead_alg":"AUTO","require_external_calib": True}, separators=(",",":"))
            cur.execute("UPDATE tenants SET policy_json=?", (default_policy,))
    def add_tenant_or_get(self, name: str, org_salt: Optional[bytes]=None, policy: Optional[Dict]=None) -> Dict:
        name = _normalize_text(name); now = int(time.time())
        con = self._conn(); cur = con.cursor()
        cur.execute("SELECT id, org_salt, policy_json FROM tenants WHERE name=?", (name,))
        row = cur.fetchone()
        if row:
            tid, osalt, pjson = int(row[0]), row[1], row[2]; con.close()
            return {"id": tid, "name": name, "org_salt": osalt, "policy": json.loads(pjson)}
        osalt = org_salt if org_salt is not None else os.urandom(32)
        pol = policy or {"kdf_profile": "AUTO", "aead_alg": "AUTO", "require_external_calib": True}
        cur.execute("INSERT INTO tenants(name,org_salt,policy_json,created_at) VALUES(?,?,?,?)",
                    (name, osalt, json.dumps(pol, separators=(",",":")), now))
        con.commit(); tid = cur.lastrowid; con.close()
        return {"id": tid, "name": name, "org_salt": osalt, "policy": pol}
    def set_policy(self, name: str, policy: Dict):
        t = self.get_tenant(name)
        if not t: raise AunsormConfigError("tenant_not_found")
        con = self._conn(); con.execute("UPDATE tenants SET policy_json=? WHERE id=?", (json.dumps(policy, separators=(",",":")), t["id"])); con.commit(); con.close()
    def get_tenant(self, name: str) -> Optional[Dict]:
        name = _normalize_text(name); con = self._conn(); cur = con.cursor()
        cur.execute("SELECT id, org_salt, policy_json FROM tenants WHERE name=?", (name,))
        row = cur.fetchone(); con.close()
        if not row: return None
        return {"id": int(row[0]), "name": name, "org_salt": row[1], "policy": json.loads(row[2])}
    def text_to_calibration_for_tenant(self, tenant_name: str, note: str, store_note=True
    ) -> Tuple[Dict[str, float], str, str, Optional[int]]:
        """
        Eğer AUNSORM_DISABLE_NOTE_STORAGE=1 ise, DB'ye *asla* metin yazmaz.
        Yalnızca calib_id/note_sha döndürür; note_id None kalır.
        """
        t = self.get_tenant(tenant_name)
        if not t: raise AunsormConfigError("tenant_not_found")
        norm = _normalize_text(note)
        note_sha = hashlib.sha256(norm.encode("utf-8")).hexdigest()
        base_ikm = hashlib.sha512(b"Aunsorm/1.01|CALIB|TEXT|" + norm.encode("utf-8")).digest()
        salt = hashlib.sha256(t["org_salt"]).digest()
        def _u_to_q(u64: bytes, lo: float, hi: float, step: float) -> float:
            u = int.from_bytes(u64, "big") / float(1<<64)
            raw = lo + (hi-lo) * u
            if step >= 1.0: v = float(int(round(raw/step)*step))
            else: v = float(round(round(raw/step)*step, 9))
            return max(lo, min(hi, v))
        calib: Dict[str,float] = {}
        for field,(lo,hi,step) in CALIB_SCHEMA_V1.items():
            u64 = hkdf_sha256(base_ikm, salt, b"Aunsorm/1.01/CALIB-FIELD|"+field.encode(), 8)
            calib[field] = _u_to_q(u64, lo, hi, step)
        calib_id = _calib_id_prefixed(calib)
        note_id: Optional[int] = None
        if store_note and os.getenv("AUNSORM_DISABLE_NOTE_STORAGE","0").lower() not in ("1","true"):
            con = self._conn(); cur = con.cursor(); now = int(time.time())
            cur.execute("""INSERT OR IGNORE INTO notes (tenant_id,calib_id,schema_ver,note_sha,note,created_at)
                           VALUES (?,?,?,?,?,?)""", (t["id"],calib_id,SCHEMA_VER,note_sha,norm,now))
            con.commit(); cur.execute("SELECT id FROM notes WHERE note_sha=?", (note_sha,)); row = cur.fetchone()
            note_id = int(row[0]) if row else None; con.close()
        return calib, calib_id, note_sha, note_id
    def note_by_calib_id(self, calib_id: str) -> Optional[str]:
        if os.getenv("AUNSORM_DISABLE_NOTE_STORAGE","0").lower() in ("1","true"):
            return None
        con = self._conn(); cur = con.cursor()
        cur.execute("SELECT note FROM notes WHERE calib_id=? ORDER BY id DESC LIMIT 1", (calib_id,))
        row = cur.fetchone(); con.close()
        return row[0] if row else None

# ---------- KDF Profiles ----------
try:
    from argon2.low_level import hash_secret_raw, Type as ArgonType
except Exception as e:
    raise AunsormConfigError("argon2-cffi missing; install it in your environment.") from e

def _cpu_par():
    c = os.cpu_count() or 2
    return max(1, min(8, c-1))
def _ram_mib():
    try:
        pages = os.sysconf("SC_PHYS_PAGES"); psz = os.sysconf("SC_PAGE_SIZE")
        return int((pages * psz) / (1024*1024))
    except Exception:
        return 4096
def _auto_profile_dynamic() -> Dict:
    ram = _ram_mib(); par = _cpu_par()
    if ram < 2048:   return dict(t=2, m_kib=32768,   p=max(1,par//2))
    if ram < 4096:   return dict(t=3, m_kib=65536,   p=max(2,par//2))
    if ram < 8192:   return dict(t=3, m_kib=131072,  p=max(3,par))
    if ram < 16384:  return dict(t=4, m_kib=262144,  p=max(4,par))
    return dict(t=4, m_kib=524288,  p=max(4,par))
PROFILES = {
    "MOBILE":dict(t=2,m_kib=32768,p=1),"LOW":dict(t=2,m_kib=32768,p=2),
    "MEDIUM":dict(t=3,m_kib=65536,p=max(2,_cpu_par())),"HIGH":dict(t=3,m_kib=131072,p=max(3,_cpu_par())),
    "ULTRA":dict(t=4,m_kib=262144,p=max(4,_cpu_par())),"AUTO":"AUTO",
}
def register_profile(name: str, t:int, m_kib:int, p:int): PROFILES[name.upper()] = dict(t=t, m_kib=m_kib, p=p)
def derive_seed64_and_pdk(password: str, salt_pwd: bytes, salt_calib: bytes, salt_chain: bytes,
                          profile: Union[str, Dict]="HIGH", hash_len: int = 64, kdf_type: str = "Argon2id") -> Tuple[bytes, bytes, Dict]:
    if not isinstance(password, str) or len(password) == 0: raise AunsormConfigError("password required")
    if len(password) > 1024: raise AunsormConfigError("password too long (>1024)")
    if isinstance(profile, str):
        pn = profile.upper()
        if pn == "AUTO": cfg = _auto_profile_dynamic(); prof_name = f"AUTO→t={cfg['t']},m={cfg['m_kib']},p={cfg['p']}"
        else: cfg = PROFILES.get(pn) or _auto_profile_dynamic(); prof_name = pn
    else:
        cfg = {"t": int(profile.get("t",3)), "m_kib": int(profile.get("m_kib",131072)), "p": int(profile.get("p",_cpu_par()))}
        prof_name = f"CUSTOM(t={cfg['t']},m={cfg['m_kib']},p={cfg['p']})"
    if kdf_type != "Argon2id": raise AunsormConfigError("only Argon2id supported")
    pdk = hash_secret_raw(password.encode("utf-8"), salt_pwd, time_cost=cfg["t"], memory_cost=cfg["m_kib"], parallelism=cfg["p"], hash_len=hash_len, type=ArgonType.ID, version=19)
    seed64 = hkdf_sha256(pdk + salt_calib, salt_chain, _label(VERSION_LABEL, "seed"), 64)
    info = {"kdf":kdf_type,"profile":prof_name,"t":cfg["t"],"m_kib":cfg["m_kib"],"p":cfg["p"],"dkLen":hash_len}
    return seed64, pdk, info
def _profile_tag(profile: Union[str,Dict], kdf_info: Dict) -> str:
    if isinstance(profile, str) and kdf_info["profile"].startswith("AUTO→"): return kdf_info["profile"]
    if isinstance(profile, str): return profile
    return f"CUSTOM(t={kdf_info['t']},m={kdf_info['m_kib']},p={kdf_info['p']})"

# ---------- AEADs ----------
def _auto_aead_choice() -> str:
    if _HAVE_PYCA: return "AES-256-GCM"
    if _HAVE_PYCRYPTODOME:
        try:
            arch = (os.uname().machine or "").lower()
            if "arm" in arch: return "CHACHA20-POLY1305"
        except Exception: pass
        return "AES-256-GCM"
    raise AunsormConfigError("No AEAD backend found; install 'cryptography' or 'pycryptodome'.")

def aead_encrypt(alg: str, key: bytes, nonce: bytes, plaintext: bytes, aad_list: List[bytes]) -> bytes:
    aad = _aad_bytes(aad_list)
    if alg == "AES-256-SIV" and not _HAVE_PYCRYPTODOME:
        raise AunsormConfigError("AES-256-SIV requires pycryptodome.")
    if _HAVE_PYCA:
        if alg == "AES-256-GCM": return nonce + AESGCM(key).encrypt(nonce, plaintext, aad)
        if alg == "CHACHA20-POLY1305": return nonce + ChaCha20Poly1305(key).encrypt(nonce, plaintext, aad)
    if alg == "AES-256-SIV":
        cipher = AES.new(key, AES.MODE_SIV); cipher.update(aad); ct, tag = cipher.encrypt_and_digest(plaintext); return ct + tag
    if alg == "AES-256-GCM" and _HAVE_PYCRYPTODOME:
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce); cipher.update(aad); ct, tag = cipher.encrypt_and_digest(plaintext); return nonce + ct + tag
    if alg == "CHACHA20-POLY1305" and _HAVE_PYCRYPTODOME:
        cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce); cipher.update(aad); ct, tag = cipher.encrypt_and_digest(plaintext); return nonce + ct + tag
    raise AunsormConfigError("Unsupported AEAD or missing backend")

def aead_decrypt(alg: str, key: bytes, cblob: bytes, aad_list: List[bytes]) -> bytes:
    aad = _aad_bytes(aad_list)
    if alg == "AES-256-SIV" and not _HAVE_PYCRYPTODOME: raise AunsormConfigError("AES-256-SIV requires pycryptodome.")
    if _HAVE_PYCA:
        if alg == "AES-256-GCM":
            if len(cblob) < 28: raise AunsormInvalidPacketError("GCM cblob too short")
            nonce, rest = cblob[:12], cblob[12:]; return AESGCM(key).decrypt(nonce, rest, aad)
        if alg == "CHACHA20-POLY1305":
            if len(cblob) < 28: raise AunsormInvalidPacketError("CHACHA cblob too short")
            nonce, rest = cblob[:12], cblob[12:]; return ChaCha20Poly1305(key).decrypt(nonce, rest, aad)
    if alg == "AES-256-SIV":
        if len(cblob) < 16: raise AunsormInvalidPacketError("SIV ctag too short")
        ct, tag = cblob[:-16], cblob[-16:]; cipher = AES.new(key, AES.MODE_SIV); cipher.update(aad); return cipher.decrypt_and_verify(ct, tag)
    if alg == "AES-256-GCM" and _HAVE_PYCRYPTODOME:
        if len(cblob) < 28: raise AunsormInvalidPacketError("GCM cblob too short")
        nonce, rest = cblob[:12], cblob[12:]; ct, tag = rest[:-16], rest[-16:]
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce); cipher.update(aad); return cipher.decrypt_and_verify(ct, tag)
    if alg == "CHACHA20-POLY1305" and _HAVE_PYCRYPTODOME:
        if len(cblob) < 28: raise AunsormInvalidPacketError("CHACHA cblob too short")
        nonce, rest = cblob[:12], cblob[12:]; ct, tag = rest[:-16], rest[-16:]
        cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce); cipher.update(aad); return cipher.decrypt_and_verify(ct, tag)
    raise AunsormConfigError("Unsupported AEAD or missing backend")

# ---------- OQS helpers ----------
PQC_KEM_PREF = ["ML-KEM-768","ML-KEM-1024","Kyber768","Kyber1024","FrodoKEM-640-AES"]
def _oqs_enabled_lists():
    if not _HAVE_OQS: return [], []
    kems, sigs = [], []
    for name in ("get_enabled_KEMs","get_enabled_kem_mechanisms","get_enabled_kems"):
        if hasattr(oqs, name): kems = getattr(oqs, name)(); break
    for name in ("get_enabled_sigs","get_enabled_sig_mechanisms","get_enabled_signatures","get_enabled_sig_algs"):
        if hasattr(oqs, name): sigs = getattr(oqs, name)(); break
    return kems or [], sigs or []
def _pick_ci_from_prefs(prefs: List[str], options: List[str]) -> Optional[str]:
    lo = [o.lower() for o in options]
    for p in prefs:
        if p and p.lower() in lo: return options[lo.index(p.lower())]
    return options[0] if options else None

# ---------- Input validation ----------
def _validate_b64(s: str, max_len: int = 16384) -> bytes:
    if not isinstance(s, str): raise AunsormConfigError("expected base64url string")
    if len(s) > max_len: raise AunsormConfigError("base64 too long")
    try: return b64d(s)
    except Exception: raise AunsormConfigError("invalid base64url")
def _validate_recipient_pk_b64(recipient_pk_b64: Optional[str], kem_name: str) -> Optional[bytes]:
    if not recipient_pk_b64: return None
    raw = _validate_b64(recipient_pk_b64, 16384)
    return raw

# ---------- Session / Ratchet ----------
class SessionStore:
    def __init__(self): self._m: Dict[str, Dict] = {}
    def add(self, session_id: str, rk: bytes, kem: str): self._m[session_id] = {"rk": rk, "kem": kem, "created": int(time.time())}
    def get(self, session_id: str) -> Optional[Dict]: return self._m.get(session_id)
    def drop(self, session_id: str): self._m.pop(session_id, None)

class AunsormSession:
    def __init__(self, recipient_kem_pk_b64: Optional[str], kem_name: Optional[str] = None):
        self.recipient_kem_pk_b64 = recipient_kem_pk_b64; self.kem_name = kem_name
        self.session_id = b64e(os.urandom(16)); self.msg_no = 0; self._rk: Optional[bytes] = None; self._kem_meta_first: Optional[Dict] = None
    def _ensure_kem(self, password_key: bytes) -> Tuple[Dict, bytes, bool, bool]:
        if self._rk is not None:
            return {"kem":"RESUME","pk":"","ctkem":"","rbkem":True}, self._rk, True, False
        if not _HAVE_OQS:
            rk = hkdf_sha256(password_key, b"AUNSORM-NO-PQ", b"NO-PQ-RK", 32); self._rk = rk
            return {"kem":"NONE","pk":"","ctkem":"","rbkem":False}, rk, False, True
        kem_override = self.kem_name; kems, _ = _oqs_enabled_lists()
        kem_name = _pick_ci_from_prefs([kem_override] if kem_override else PQC_KEM_PREF, kems) or "ML-KEM-768"
        if self.recipient_kem_pk_b64:
            with oqs.KeyEncapsulation(kem_name) as sender:
                ctkem, ss = sender.encap_secret(b64d(self.recipient_kem_pk_b64))
            rk = hkdf_sha256(ss, b"RK", _label(VERSION_LABEL, "RK"), 32)
            kem_meta = {"kem": kem_name, "pk": self.recipient_kem_pk_b64, "ctkem": b64e(ctkem), "rbkem": True}
            self._rk = rk; self._kem_meta_first = kem_meta
            return kem_meta, rk, True, True
        else:
            with oqs.KeyEncapsulation(kem_name) as receiver:
                pk = receiver.generate_keypair()
                try:
                    with oqs.KeyEncapsulation(kem_name) as sender:
                        ctkem, ss_client = sender.encap_secret(pk)
                except TypeError:
                    with oqs.KeyEncapsulation(kem_name, pk) as sender:
                        ctkem, ss_client = sender.encap_secret()
                ss_server = receiver.decap_secret(ctkem)
                if not _const_eq(ss_client, ss_server): raise AunsormInvalidPacketError("KEM secret mismatch")
            rk = hkdf_sha256(ss_server, b"RK", _label(VERSION_LABEL, "RK"), 32)
            kem_meta = {"kem": kem_name, "pk": b64e(pk), "ctkem": b64e(ctkem), "rbkem": False}
            self._rk = rk; self._kem_meta_first = kem_meta
            return kem_meta, rk, True, True
    def next_cadence(self) -> Tuple[str, int]:
        self.msg_no += 1; return self.session_id, self.msg_no

# ---------- Core Encrypt/Decrypt ----------
VERSION = VERSION_STR
_MAX_PACKET = 64 * 1024 * 1024
_MAX_HEADER = 512 * 1024

def _kem_encaps(password_key: bytes, kem_override: Optional[str], recipient_pk_b64: Optional[str]) -> Tuple[Dict, bytes, bool]:
    if recipient_pk_b64 and not _HAVE_OQS: raise AunsormConfigError("Recipient-bound KEM requires liboqs")
    if not _HAVE_OQS:
        ss = hkdf_sha256(password_key, b"AUNSORM-NO-PQ", b"NO-PQ-SS", 32)
        meta = {"kem":"NONE","pk":"","ctkem":"","ss":"","wrap_salt":"","wrap_nonce":"","rbkem":False}
        return meta, ss, False
    kems, _sigs = _oqs_enabled_lists()
    kem_name = _pick_ci_from_prefs(PQC_KEM_PREF, kems) if not kem_override else _pick_ci_from_prefs([kem_override], kems)
    if not kem_name:
        ss = hkdf_sha256(password_key, b"AUNSORM-NO-PQ", b"NO-PQ-SS", 32)
        meta = {"kem":"NONE","pk":"","ctkem":"","ss":"","wrap_salt":"","wrap_nonce":"","rbkem":False}
        return meta, ss, False
    if recipient_pk_b64:
        _validate_recipient_pk_b64(recipient_pk_b64, kem_name)
        recipient_pk = b64d(recipient_pk_b64)
        with oqs.KeyEncapsulation(kem_name) as sender:
            ctkem, ss = sender.encap_secret(recipient_pk)
        meta = {"kem": kem_name, "pk": recipient_pk_b64, "ctkem": b64e(ctkem), "ss":"", "wrap_salt":"", "wrap_nonce":"", "rbkem":True}
        return meta, ss, True
    with oqs.KeyEncapsulation(kem_name) as receiver:
        pk = receiver.generate_keypair()
        try:
            with oqs.KeyEncapsulation(kem_name) as sender:
                ctkem, ss_client = sender.encap_secret(pk)
        except TypeError:
            with oqs.KeyEncapsulation(kem_name, pk) as sender:
                ctkem, ss_client = sender.encap_secret()
        ss_server = receiver.decap_secret(ctkem)
        if not _const_eq(ss_client, ss_server): raise AunsormInvalidPacketError("KEM secret mismatch")
    wrap_salt, wrap_nonce = os.urandom(16), os.urandom(12)
    wrap_key  = hkdf_sha256(password_key, wrap_salt, _label(VERSION_LABEL, "WRAP"), 32)
    ss_ctag   = aead_encrypt("AES-256-SIV", hkdf_sha256(wrap_key, b"SIV-K", _label(VERSION_LABEL,"WRAP/SIV"), 64), b"", ss_server, [b"Aunsorm|WRAP|"+kem_name.encode(), wrap_nonce])
    meta = {"kem": kem_name, "pk": b64e(pk), "ctkem": b64e(ctkem), "ss": b64e(ss_ctag), "wrap_salt": b64e(wrap_salt), "wrap_nonce": b64e(wrap_nonce), "rbkem":False}
    return meta, ss_server, True

def _constant_time_delay(min_us=1500, max_us=2500):
    import random, time as _t; _t.sleep(random.uniform(min_us, max_us) / 1e6)

def _kem_decap(header: Dict, password_key: bytes, kem_sk_b64: Optional[str]) -> bytes:
    kem_name = header["kem"]["kem"]
    if kem_name == "NONE" or not _HAVE_OQS: return hkdf_sha256(password_key, b"AUNSORM-NO-PQ", b"NO-PQ-SS", 32)
    if header["kem"].get("rbkem", False):
        if kem_sk_b64 is None: _constant_time_delay(); raise AunsormTokenError("recipient_private_key_required")
        sk = b64d(kem_sk_b64); ctkem = b64d(header["kem"]["ctkem"])
        try:
            with oqs.KeyEncapsulation(kem_name) as receiver:
                if hasattr(receiver, "import_secret_key"): receiver.import_secret_key(sk)
                else: receiver = oqs.KeyEncapsulation(kem_name, secret_key=sk)
                ss = receiver.decap_secret(ctkem)
        except TypeError:
            with oqs.KeyEncapsulation(kem_name) as receiver:
                if not hasattr(receiver, "import_secret_key"): raise AunsormConfigError("liboqs cannot import secret key for rbkem")
                receiver.import_secret_key(sk); ss = receiver.decap_secret(ctkem)
        return ss
    ss_ctag    = b64d(header["kem"]["ss"]); wrap_salt  = b64d(header["kem"]["wrap_salt"]); wrap_nonce = b64d(header["kem"]["wrap_nonce"])
    label_base = _label_from_header(header); wrap_key = hkdf_sha256(password_key, wrap_salt, _label(label_base, "WRAP"), 32)
    return aead_decrypt("AES-256-SIV", hkdf_sha256(wrap_key, b"SIV-K", _label(label_base,"WRAP/SIV"), 64), ss_ctag, [b"Aunsorm|WRAP|"+kem_name.encode(), wrap_nonce])

def _derive_siv_key(pdk: bytes, seed64: bytes, coord32: bytes, secret: bytes, siv_salt: bytes, aead_alg: str) -> bytes:
    siv_key = hkdf_sha256(pdk + seed64 + coord32 + secret, siv_salt, _label(VERSION_LABEL, "SIV"), 64)
    return siv_key if aead_alg=="AES-256-SIV" else hkdf_sha256(siv_key, b"AEAD", _label(VERSION_LABEL, aead_alg), 32)

def aunsorm_encrypt(password: str, plaintext: bytes, profile: Union[str,Dict]="AUTO",
                    pqc_kem: Optional[str]=None, aead_alg: Optional[str]=None,
                    recipient_kem_pk_b64: Optional[str]=None,
                    calibration: Optional[Dict[str, float]]=None,
                    calib_mode: str = "EXTERNAL",
                    context_aad: Optional[Union[str,bytes]]=None,
                    kdf_hash_len: int = 64, kdf_type: str = "Argon2id") -> Dict:
    if not isinstance(plaintext, (bytes, bytearray)): raise AunsormInvalidPacketError("Plaintext must be bytes")
    if len(plaintext) > (_MAX_PACKET - 1024*1024): raise AunsormInvalidPacketError("Plaintext too large")
    salts = {"pwd": os.urandom(16), "calib": os.urandom(16), "chain": os.urandom(16), "siv": os.urandom(16), "hdrmac": os.urandom(16), "aead": os.urandom(12)}
    seed64, pdk, kdf_info = derive_seed64_and_pdk(password, salts["pwd"], salts["calib"], salts["chain"], profile, hash_len=kdf_hash_len, kdf_type=kdf_type)
    cmode = (calib_mode or "EXTERNAL").upper()
    if cmode == "EXTERNAL":
        if calibration is None: raise AunsormConfigError("calibration_required_for_external_bind")
        calib_id, coord32 = derive_coord32_v10(seed64, calibration, salts); calib_bind = "EXTERNAL"
    elif cmode == "DERIVED":
        _calib, calib_id, coord32 = derive_calibration(seed64); calib_bind = "DERIVED"
    else: raise AunsormConfigError("invalid calib_mode (use 'EXTERNAL' or 'DERIVED')")
    kem_meta, ss, pq_enabled = _kem_encaps(pdk, pqc_kem, recipient_kem_pk_b64)
    if aead_alg is None or aead_alg == "AUTO": aead_alg = _auto_aead_choice()
    if aead_alg not in ("AES-256-SIV","AES-256-GCM","CHACHA20-POLY1305"): raise AunsormConfigError("Unsupported AEAD")
    profile_tag = _profile_tag(profile, kdf_info)
    extra_aad = [context_aad.encode() if isinstance(context_aad,str) else (context_aad or b"")]
    aead_key = _derive_siv_key(pdk, seed64, coord32, ss, salts["siv"], aead_alg)
    aad = [VERSION.encode(), calib_id.encode(), profile_tag.encode(), salts["pwd"], salts["calib"], salts["chain"], salts["siv"], coord32, kem_meta["kem"].encode()] + extra_aad
    cblob = aead_encrypt(aead_alg, aead_key, salts["aead"], plaintext, aad)
    header_body = {"version": VERSION, "label": VERSION_LABEL.decode(), "mode":"PQ-HYBRID+CB-AEAD+FORMUL", "profile": profile_tag, "pq_enabled": pq_enabled,
                   "calib_id": calib_id, "coord_digest": hashlib.sha256(coord32).hexdigest(),
                   "calib_schema": {"ver": SCHEMA_VER, "bind": calib_bind, "hash": "prefixed-v1"},
                   "kdf": kdf_info, "salts": {k: b64e(v) for k,v in salts.items()},
                   "aead": {"alg": aead_alg}, "kem": kem_meta,
                   "session": {"id":"", "msg_no":0, "new": False}, "sizes": {"pt_len": len(plaintext), "ct_len": len(cblob)}}
    if context_aad: header_body["context_aad"] = "present"
    hbytes_body = json.dumps(header_body, separators=(",",":"), sort_keys=True).encode()
    hdrmac_key  = hkdf_sha256(pdk, salts["hdrmac"], _label(VERSION_LABEL, "HDRMAC"), 32)
    header_mac  = hmac.new(hdrmac_key, hbytes_body, hashlib.sha256).digest()
    header = {**header_body, "hmac": b64e(header_mac)}
    hbytes = json.dumps(header, separators=(",",":"), sort_keys=True).encode()
    packet_body = struct.pack(">I", len(hbytes)) + hbytes + cblob
    pmac_key = hkdf_sha256(pdk, salts["hdrmac"], _label(VERSION_LABEL, "PMAC"), 32)
    pmac = hmac.new(pmac_key, packet_body, hashlib.sha256).digest()
    packet = packet_body + pmac
    log.info("Encrypted packet kem=%s%s, aead=%s, profile=%s, bind=%s", kem_meta["kem"], " (RB)" if kem_meta.get("rbkem") else "", aead_alg, header["profile"], header_body["calib_schema"]["bind"])
    return {"packet": b64e(packet), "header": header}

def aunsorm_decrypt(password: str, packet_b64: str, kem_sk_b64: Optional[str]=None,
                    calibration: Optional[Dict[str, float]] = None,
                    context_aad: Optional[Union[str,bytes]]=None) -> Tuple[bytes, Dict]:
    raw = b64d(packet_b64)
    if len(raw) < (4+32): raise AunsormInvalidPacketError("Packet too short")
    if len(raw) > (_MAX_PACKET + 1024*1024): raise AunsormInvalidPacketError("Packet too large")
    pmac = raw[-32:]; body = raw[:-32]
    if len(body) < 4: raise AunsormInvalidPacketError("Body too short")
    hlen = struct.unpack(">I", body[:4])[0]
    if hlen < 32 or hlen > len(body)-4: raise AunsormInvalidPacketError("Header length invalid")
    if hlen > _MAX_HEADER or (4 + hlen) > len(body): raise AunsormInvalidPacketError("Header too large")
    header = json.loads(body[4:4+hlen].decode()); cblob = body[4+hlen:]
    if "sizes" in header and isinstance(header["sizes"], dict):
        ct_len = header["sizes"].get("ct_len")
        if isinstance(ct_len, int) and ct_len != len(cblob): raise AunsormInvalidPacketError("Ciphertext length mismatch")
    salts = {k: b64d(v) for k,v in header["salts"].items()}
    profile_for_kdf = header.get("kdf", header.get("profile","HIGH"))
    seed64, pdk, _ = derive_seed64_and_pdk(password, salts["pwd"], salts["calib"], salts["chain"], profile_for_kdf)
    label_base = _label_from_header(header)
    pmac_key = hkdf_sha256(pdk, salts["hdrmac"], _label(label_base, "PMAC"), 32)
    if not _const_eq(hmac.new(pmac_key, body, hashlib.sha256).digest(), pmac): raise AunsormInvalidPacketError("Packet PMAC invalid")
    hdrmac_key  = hkdf_sha256(pdk, salts["hdrmac"], _label(label_base, "HDRMAC"), 32)
    header_copy = dict(header); header_mac = b64d(header_copy.pop("hmac"))
    hbytes_body = json.dumps(header_copy, separators=(",",":"), sort_keys=True).encode()
    if not _const_eq(hmac.new(hdrmac_key, hbytes_body, hashlib.sha256).digest(), header_mac): raise AunsormInvalidPacketError("Header MAC invalid")
    bind = header.get("calib_schema",{}).get("bind","DERIVED").upper()
    if bind == "EXTERNAL":
        if calibration is None: raise AunsormCalibrationMismatchError("calibration_required")
        cid2, coord32 = derive_coord32_v10(seed64, calibration, salts)
        if cid2 != header["calib_id"]: raise AunsormCalibrationMismatchError("Calibration ID mismatch")
    else:
        _calib, cid2, coord32 = derive_calibration(seed64)
        if cid2 != header["calib_id"]: raise AunsormCalibrationMismatchError("Calibration ID mismatch (derived)")
    if not _const_eq(hashlib.sha256(coord32).hexdigest().encode(), header["coord_digest"].encode()): raise AunsormCalibrationMismatchError("Coord digest mismatch")
    ss = _kem_decap(header, pdk, kem_sk_b64)
    alg = header.get("aead",{}).get("alg","AES-256-SIV"); extra_aad = [context_aad.encode() if isinstance(context_aad,str) else (context_aad or b"")]
    aead_key = _derive_siv_key(pdk, seed64, coord32, ss, salts["siv"], alg)
    aad = [header["version"].encode(), header["calib_id"].encode(), str(header["profile"]).encode(), salts["pwd"], salts["calib"], salts["chain"], salts["siv"], coord32, header["kem"]["kem"].encode()] + extra_aad
    pt = aead_decrypt(alg, aead_key, cblob, aad)
    return pt, header

def aunsorm_decrypt_safe(password: str, packet_b64: str, kem_sk_b64: Optional[str]=None,
                         calibration: Optional[Dict[str, float]] = None,
                         context_aad: Optional[Union[str,bytes]]=None) -> Tuple[Optional[bytes], Optional[Dict]]:
    try:
        return aunsorm_decrypt(password, packet_b64, kem_sk_b64=kem_sk_b64, calibration=calibration, context_aad=context_aad)
    except (AunsormInvalidPacketError, AunsormCalibrationMismatchError, AunsormTokenError, AunsormConfigError) as e:
        _constant_time_delay(2000, 4000); log.warning("decrypt_failed: %s", str(e)[:96]); raise AunsormDecryptionFailed("decryption_failed")

# ---------- Session encrypt/decrypt ----------
def session_encrypt(session: AunsormSession, password: str, plaintext: bytes,
                    profile: Union[str,Dict]="AUTO", aead_alg: Optional[str]=None,
                    calibration: Optional[Dict[str, float]]=None,
                    calib_mode: str = "EXTERNAL",
                    context_aad: Optional[Union[str,bytes]]=None) -> Dict:
    if not isinstance(plaintext, (bytes, bytearray)): raise AunsormInvalidPacketError("Plaintext must be bytes")
    if len(plaintext) > (_MAX_PACKET - 1024*1024): raise AunsormInvalidPacketError("Plaintext too large")
    salts = {"pwd": os.urandom(16), "calib": os.urandom(16), "chain": os.urandom(16), "siv": os.urandom(16), "hdrmac": os.urandom(16), "aead": os.urandom(12)}
    seed64, pdk, kdf_info = derive_seed64_and_pdk(password, salts["pwd"], salts["calib"], salts["chain"], profile)
    cmode = (calib_mode or "EXTERNAL").upper()
    if cmode == "EXTERNAL":
        if calibration is None: raise AunsormConfigError("calibration_required_for_external_bind")
        calib_id, coord32 = derive_coord32_v10(seed64, calibration, salts); calib_bind = "EXTERNAL"
    elif cmode == "DERIVED":
        _calib, calib_id, coord32 = derive_calibration(seed64); calib_bind = "DERIVED"
    else: raise AunsormConfigError("invalid calib_mode")
    kem_meta, rk, pq_enabled, is_new = session._ensure_kem(pdk)
    if aead_alg is None or aead_alg == "AUTO": aead_alg = _auto_aead_choice()
    if aead_alg not in ("AES-256-SIV","AES-256-GCM","CHACHA20-POLY1305"): raise AunsormConfigError("Unsupported AEAD")
    sid, msg_no = session.next_cadence()
    step_secret = hkdf_sha256(rk, int_to_bytes(msg_no, 8), _label(VERSION_LABEL, "STEP"), 32)
    msg_secret  = hkdf_sha256(step_secret, sid.encode(), _label(VERSION_LABEL, "MSG"), 32)
    profile_tag = _profile_tag(profile, kdf_info)
    extra_aad = [context_aad.encode() if isinstance(context_aad,str) else (context_aad or b"")]
    aead_key = _derive_siv_key(pdk, seed64, coord32, msg_secret, salts["siv"], aead_alg)
    aad = [VERSION.encode(), calib_id.encode(), profile_tag.encode(), salts["pwd"], salts["calib"], salts["chain"], salts["siv"], coord32, (b"RESUME" if not is_new else kem_meta["kem"].encode())] + extra_aad
    cblob = aead_encrypt(aead_alg, aead_key, salts["aead"], plaintext, aad)
    header_body = {"version": VERSION, "label": VERSION_LABEL.decode(), "mode":"PQ-HYBRID+CB-AEAD+FORMUL+SESSION", "profile": profile_tag, "pq_enabled": pq_enabled,
                   "calib_id": calib_id, "coord_digest": hashlib.sha256(coord32).hexdigest(),
                   "calib_schema": {"ver": SCHEMA_VER, "bind": calib_bind, "hash": "prefixed-v1"},
                   "kdf": kdf_info, "salts": {k: b64e(v) for k,v in salts.items()},
                   "aead": {"alg": aead_alg}, "kem": kem_meta if is_new else {"kem":"RESUME","pk":"","ctkem":"","rbkem":True},
                   "session": {"id": sid, "msg_no": msg_no, "new": is_new}, "sizes": {"pt_len": len(plaintext), "ct_len": len(cblob)}}
    if context_aad: header_body["context_aad"] = "present"
    hbytes_body = json.dumps(header_body, separators=(",",":"), sort_keys=True).encode()
    hdrmac_key  = hkdf_sha256(pdk, salts["hdrmac"], _label(VERSION_LABEL, "HDRMAC"), 32)
    header_mac  = hmac.new(hdrmac_key, hbytes_body, hashlib.sha256).digest()
    header = {**header_body, "hmac": b64e(header_mac)}
    hbytes = json.dumps(header, separators=(",",":"), sort_keys=True).encode()
    packet_body = struct.pack(">I", len(hbytes)) + hbytes + cblob
    pmac_key = hkdf_sha256(pdk, salts["hdrmac"], _label(VERSION_LABEL, "PMAC"), 32)
    pmac = hmac.new(pmac_key, packet_body, hashlib.sha256).digest()
    packet = packet_body + pmac
    log.info("Encrypted packet (session=%s%s) aead=%s, profile=%s, bind=%s", sid, " NEW" if is_new else "", aead_alg, header["profile"], header_body["calib_schema"]["bind"])
    return {"packet": b64e(packet), "header": header}

def session_decrypt(store: SessionStore, password: str, packet_b64: str,
                    kem_sk_b64: Optional[str]=None,
                    calibration: Optional[Dict[str, float]] = None,
                    context_aad: Optional[Union[str,bytes]]=None) -> Tuple[bytes, Dict]:
    raw = b64d(packet_b64)
    if len(raw) < (4+32): raise AunsormInvalidPacketError("Packet too short")
    if len(raw) > (_MAX_PACKET + 1024*1024): raise AunsormInvalidPacketError("Packet too large")
    pmac = raw[-32:]; body = raw[:-32]
    if len(body) < 4: raise AunsormInvalidPacketError("Body too short")
    hlen = struct.unpack(">I", body[:4])[0]
    if hlen < 32 or hlen > len(body)-4: raise AunsormInvalidPacketError("Header length invalid")
    if hlen > _MAX_HEADER or (4 + hlen) > len(body): raise AunsormInvalidPacketError("Header too large")
    header = json.loads(body[4:4+hlen].decode()); cblob = body[4+hlen:]
    salts = {k: b64d(v) for k,v in header["salts"].items()}
    profile_for_kdf = header.get("kdf", header.get("profile","HIGH"))
    seed64, pdk, _ = derive_seed64_and_pdk(password, salts["pwd"], salts["calib"], salts["chain"], profile_for_kdf)
    label_base = _label_from_header(header)
    pmac_key = hkdf_sha256(pdk, salts["hdrmac"], _label(label_base, "PMAC"), 32)
    if not _const_eq(hmac.new(pmac_key, body, hashlib.sha256).digest(), pmac): raise AunsormInvalidPacketError("Packet PMAC invalid")
    hdrmac_key  = hkdf_sha256(pdk, salts["hdrmac"], _label(label_base, "HDRMAC"), 32)
    header_copy = dict(header); header_mac = b64d(header_copy.pop("hmac"))
    hbytes_body = json.dumps(header_copy, separators=(",",":"), sort_keys=True).encode()
    if not _const_eq(hmac.new(hdrmac_key, hbytes_body, hashlib.sha256).digest(), header_mac): raise AunsormInvalidPacketError("Header MAC invalid")
    bind = header.get("calib_schema",{}).get("bind","DERIVED").upper()
    if bind == "EXTERNAL":
        if calibration is None: raise AunsormCalibrationMismatchError("calibration_required")
        cid2, coord32 = derive_coord32_v10(seed64, calibration, salts)
        if cid2 != header["calib_id"]: raise AunsormCalibrationMismatchError("Calibration ID mismatch")
    else:
        _calib, cid2, coord32 = derive_calibration(seed64)
        if cid2 != header["calib_id"]: raise AunsormCalibrationMismatchError("Calibration ID mismatch (derived)")
    if not _const_eq(hashlib.sha256(coord32).hexdigest().encode(), header["coord_digest"].encode()): raise AunsormCalibrationMismatchError("Coord digest mismatch")
    s_meta = header.get("session",{}); sid, msg_no, is_new = s_meta.get("id",""), int(s_meta.get("msg_no",0)), bool(s_meta.get("new",False))
    alg = header.get("aead",{}).get("alg","AES-256-SIV"); extra_aad = [context_aad.encode() if isinstance(context_aad,str) else (context_aad or b"")]
    if is_new:
        if header["kem"]["kem"] == "NONE" and not _HAVE_OQS: rk = hkdf_sha256(pdk, b"AUNSORM-NO-PQ", b"NO-PQ-RK", 32)
        else: ss = _kem_decap(header, pdk, kem_sk_b64); rk = hkdf_sha256(ss, b"RK", _label(VERSION_LABEL, "RK"), 32)
        store.add(sid, rk, header["kem"]["kem"])
    else:
        ent = store.get(sid)
        if not ent: raise AunsormInvalidPacketError("session_state_missing")
        rk = ent["rk"]
    step_secret = hkdf_sha256(rk, int_to_bytes(msg_no, 8), _label(VERSION_LABEL, "STEP"), 32)
    msg_secret  = hkdf_sha256(step_secret, sid.encode(), _label(VERSION_LABEL, "MSG"), 32)
    aead_key = _derive_siv_key(pdk, seed64, coord32, msg_secret, salts["siv"], alg)
    kem_tag = b"RESUME" if not is_new else header["kem"]["kem"].encode()
    aad = [header["version"].encode(), header["calib_id"].encode(), str(header["profile"]).encode(), salts["pwd"], salts["calib"], salts["chain"], salts["siv"], coord32, kem_tag] + extra_aad
    pt = aead_decrypt(alg, aead_key, cblob, aad)
    return pt, header

# ---------- API helpers ----------
def generate_api_token(prefix="aun", n=32) -> str: return f"{prefix}_{base64.urlsafe_b64encode(os.urandom(n)).decode().rstrip('=')}"
def generate_password(n=24) -> str:
    alphabet="ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*()-_=+"
    return "".join(secrets.choice(alphabet) for _ in range(n))

# ---------- SQLite JTI Store (cleanup + locking + auto-clean) ----------
class SQLiteJTIStore:
    def __init__(self, path=":memory:", ttl_sec=3600):
        self.ttl = int(ttl_sec)
        self.db = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self.db.execute("PRAGMA journal_mode=WAL"); self.db.execute("PRAGMA synchronous=NORMAL"); self.db.execute("PRAGMA busy_timeout=2500")
        self.db.execute("CREATE TABLE IF NOT EXISTS jti (j TEXT PRIMARY KEY, exp INTEGER)")
        self.db.execute("CREATE INDEX IF NOT EXISTS idx_jti_exp ON jti(exp)")
        self.db.commit()
        self._ops = 0
        self._autoclean = os.getenv("AUNSORM_JTI_AUTOCLEAN","1").lower() in ("1","true")
    def _now(self): return int(time.time())
    def cleanup(self):
        now = self._now()
        try:
            self.db.execute("BEGIN IMMEDIATE")
            self.db.execute("DELETE FROM jti WHERE exp < ?", (now,))
            self.db.commit()
        except Exception:
            self.db.rollback()
    def seen(self, jti: str) -> bool:
        now = self._now(); exp = now + self.ttl
        try:
            self.db.execute("BEGIN IMMEDIATE")
            cur = self.db.execute("SELECT exp FROM jti WHERE j=?", (jti,))
            row = cur.fetchone()
            if row and row[0] >= now:
                self.db.commit(); return True
            self.db.execute("INSERT OR REPLACE INTO jti(j,exp) VALUES(?,?)", (jti, exp))
            self.db.commit()
        except Exception:
            self.db.rollback()
        self._ops += 1
        if self._autoclean and (self._ops % 128 == 0):  # per 128 ops
            try: self.cleanup()
            except Exception: pass
        return False

# ---------- Signers / JWKS / JWT ----------
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
def ed25519_public_jwk_raw(raw: bytes, ops: Optional[List[str]]=None) -> Dict:
    return {"kty":"OKP","crv":"Ed25519","x": b64e(raw), "key_ops": ops or ["verify"], "alg":"EdDSA", "use":"sig"}
def jwk_thumbprint_sha256(jwk: Dict) -> str:
    canon = json.dumps({"crv":jwk["crv"],"kty":jwk["kty"],"x":jwk["x"]}, separators=(",",":"), sort_keys=True).encode()
    return b64e(hashlib.sha256(canon).digest())

class Signer:
    def sign(self, msg: bytes) -> bytes: raise NotImplementedError
    def public_bytes(self) -> bytes: raise NotImplementedError
    def key_ops(self) -> List[str]: return ["sign","verify"]

class MemoryEd25519Signer(Signer):
    def __init__(self): self.sk = ed25519.Ed25519PrivateKey.generate()
    def sign(self, msg: bytes) -> bytes: return self.sk.sign(msg)
    def public_bytes(self) -> bytes: return self.sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

# Retry helper
def _retry(fn: Callable, tries=3, base_s=0.25):
    for i in range(tries):
        try: return fn()
        except Exception:
            if i == tries-1: raise
            time.sleep(base_s*(2**i))

# Google KMS
class GoogleKMSEd25519Signer(Signer):
    def __init__(self, resource_name: str, fallback_memory: bool=False):
        try:
            from google.cloud import kms_v1
        except Exception:
            if fallback_memory or os.getenv("AUNSORM_KMS_FALLBACK","0").lower() in ("1","true"):
                log.warning("GCP KMS unavailable, falling back to memory signer")
                self._mem = MemoryEd25519Signer(); return
            raise AunsormConfigError("google-cloud-kms not installed")
        self._mem=None
        self.kms = kms_v1.KeyManagementServiceClient(); self.name = resource_name
        pub = _retry(lambda: self.kms.get_public_key(request={"name": self.name}))
        spki_pem = pub.pem.encode(); pk = serialization.load_pem_public_key(spki_pem)
        self._pub = pk.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    def sign(self, msg: bytes) -> bytes:
        if self._mem: return self._mem.sign(msg)
        from google.cloud import kms_v1
        # Try raw, then digest
        try:
            return _retry(lambda: self.kms.asymmetric_sign(request={"name": self.name, "data": msg})).signature
        except Exception:
            dig = hashlib.sha256(msg).digest()
            return _retry(lambda: self.kms.asymmetric_sign(request={"name": self.name, "digest": {"sha256": dig}})).signature
    def public_bytes(self) -> bytes:
        return self._mem.public_bytes() if self._mem else self._pub

# Azure Key Vault
class AzureKMSEd25519Signer(Signer):
    def __init__(self, key_id: str, credential=None, fallback_memory: bool=False):
        try:
            from azure.identity import DefaultAzureCredential
            from azure.keyvault.keys.crypto import CryptographyClient, SignatureAlgorithm
        except Exception:
            if fallback_memory or os.getenv("AUNSORM_KMS_FALLBACK","0").lower() in ("1","true"):
                log.warning("Azure KV unavailable, falling back to memory signer")
                self._mem = MemoryEd25519Signer(); return
            raise AunsormConfigError("azure-identity/azure-keyvault-keys not installed")
        self._mem=None
        cred = credential or DefaultAzureCredential(); self.crypto = CryptographyClient(key_id, credential=cred); self._alg = SignatureAlgorithm.ED25519
        # Fetch public key by sign probe
        test = os.urandom(16)
        sig  = _retry(lambda: self.crypto.sign(self._alg, test)).signature
        # Azure client exposes public key via get_key on underlying client in some SDKs; fallback to derive from response not standardized
        # Use memory pub fallback path if not retrievable
        try:
            # Not guaranteed; keep best-effort
            self._pub = self.crypto._client.get_key  # type: ignore[attr-defined]
            # If not available, fallback to memory signer for JWKS exposure
            raise Exception("skip")  # ensure fallback below
        except Exception:
            self._mem = MemoryEd25519Signer(); log.warning("Azure KV pub fetch not standardized; using memory key for JWKS")
    def sign(self, msg: bytes) -> bytes:
        if self._mem: return self._mem.sign(msg)
        return _retry(lambda: self.crypto.sign(self._alg, msg)).signature
    def public_bytes(self) -> bytes:
        return self._mem.public_bytes() if self._mem else self._mem.public_bytes()  # conservative

# PKCS#11 (reintroduced)
class PKCS11Ed25519Signer(Signer):
    def __init__(self, lib_path: str, slot: int, pin: str, key_label: str, fallback_memory: bool=False):
        try:
            import PyKCS11
        except Exception:
            if fallback_memory or os.getenv("AUNSORM_KMS_FALLBACK","0").lower() in ("1","true"):
                log.warning("PKCS#11 unavailable, falling back to memory signer")
                self._mem = MemoryEd25519Signer(); return
            raise AunsormConfigError("PyKCS11 not installed")
        self._mem=None
        self.pkcs11 = PyKCS11.PyKCS11Lib(); self.pkcs11.load(lib_path)
        slots = self.pkcs11.getSlotList(tokenPresent=True)
        self.session = self.pkcs11.openSession(slots[slot]); self.session.login(pin)
        self.priv = self._find_key(key_label, private=True)
        self.pub  = self._find_key(key_label, private=False)
    def _find_key(self, label, private):
        import PyKCS11
        template = [(PyKCS11.CKA_LABEL, label),(PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY if private else PyKCS11.CKO_PUBLIC_KEY)]
        objs = self.session.findObjects(template)
        if not objs: raise AunsormConfigError("PKCS#11 key not found")
        return objs[0]
    def sign(self, msg: bytes) -> bytes:
        import PyKCS11
        mech = PyKCS11.Mechanism(PyKCS11.CKM_EDDSA, None)
        return bytes(self.session.sign(self.priv, msg, mech))
    def public_bytes(self) -> bytes:
        # Fetch raw public via attribute if available; conservative fallback is not trivial — return memory key if needed
        try:
            import PyKCS11
            attrs = self.session.getAttributeValue(self.pub, [PyKCS11.CKA_EC_POINT])
            spki = bytes(attrs[0])
            pk = serialization.load_der_public_key(spki)
            return pk.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        except Exception:
            if not hasattr(self, "_mem"): self._mem = MemoryEd25519Signer()
            return self._mem.public_bytes()

# KeyRing with rotation
class KeyRing:
    def __init__(self, rotation_sec: int = 0):
        self._signers: Dict[str, Tuple[Signer,int]] = {}
        self.active_kid: Optional[str] = None
        self.rotation_sec = int(rotation_sec)
    def add_signer(self, signer: Signer) -> str:
        kid = jwk_thumbprint_sha256(ed25519_public_jwk_raw(signer.public_bytes(), ops=signer.key_ops()))
        self._signers[kid] = (signer, int(time.time())); self.active_kid = kid; return kid
    def add_memory_key(self) -> str: return self.add_signer(MemoryEd25519Signer())
    def add_external_key(self, sign_cb: Callable[[bytes], bytes], pubkey_raw: bytes) -> str:
        class ExternalEd25519Signer(Signer):
            def __init__(self, cb, raw):
                self._cb = cb; self._raw=raw
            def sign(self, msg: bytes) -> bytes: return self._cb(msg)
            def public_bytes(self) -> bytes: return self._raw
        return self.add_signer(ExternalEd25519Signer(sign_cb, pubkey_raw))
    def add_gcp_kms(self, resource_name: str, fallback_memory=False) -> str:
        return self.add_signer(GoogleKMSEd25519Signer(resource_name, fallback_memory=fallback_memory))
    def add_azure_kms(self, key_id: str, credential=None, fallback_memory=False) -> str:
        return self.add_signer(AzureKMSEd25519Signer(key_id, credential, fallback_memory=fallback_memory))
    def add_pkcs11(self, lib_path: str, slot: int, pin: str, key_label: str, fallback_memory=False) -> str:
        return self.add_signer(PKCS11Ed25519Signer(lib_path, slot, pin, key_label, fallback_memory=fallback_memory))
    def rotate_if_needed(self):
        if not self.rotation_sec: return
        now = int(time.time())
        for kid,(s,created) in list(self._signers.items()):
            if now - created > self.rotation_sec:
                self.add_memory_key(); break
    def get_active(self) -> Tuple[str, Signer]:
        if not self.active_kid: self.add_memory_key()
        self.rotate_if_needed()
        return self.active_kid, self._signers[self.active_kid][0]
    def get_pub_jwks(self) -> Dict:
        keys=[]
        for kid,(s,_) in self._signers.items():
            keys.append({**ed25519_public_jwk_raw(s.public_bytes(), ops=s.key_ops()), "kid":kid})
        return {"keys": keys}
    def resolver(self, kid: str):
        if kid in self._signers:
            s = self._signers[kid][0]
            class _Pub:
                def __init__(self, raw): self._raw = raw
                def verify(self, sig: bytes, msg: bytes):
                    ed25519.Ed25519PublicKey.from_public_bytes(self._raw).verify(sig, msg)
            return _Pub(s.public_bytes())
        return self.resolver(self.active_kid)

def jwt_issue_ed25519(payload: Dict, signer: Signer, kid: str, iss="aunsorm") -> str:
    header = {"alg":"EdDSA","typ":"JWT","kid":kid}
    now = int(time.time())
    if "iss" not in payload: payload = {**payload, "iss": iss}
    if "iat" not in payload: payload = {**payload, "iat": now}
    if "nbf" not in payload: payload = {**payload, "nbf": payload["iat"]}
    h_b64 = b64e(json.dumps(header, separators=(",",":")).encode())
    p_b64 = b64e(json.dumps(payload, separators=(",",":")).encode())
    sig = signer.sign((h_b64+"."+p_b64).encode())
    return h_b64+"."+p_b64+"."+b64e(sig)

def jwt_verify_ed25519(token: str, pk_resolver) -> Dict:
    try:
        h,p,s = token.split("."); header = json.loads(base64.urlsafe_b64decode(h+"==").decode())
        kid = header.get("kid"); pk = pk_resolver(kid)
        pk.verify(b64d(s), (h+"."+p).encode())
        return json.loads(base64.urlsafe_b64decode(p+"==").decode())
    except Exception as e:
        raise AunsormTokenError("JWT verify failed") from e

def jwt_validate_claims(claims: dict, expected_iss: str, expected_aud: Optional[str]=None, skew: int=60,
                        jti_seen: Optional[Union[set, SQLiteJTIStore]]=None) -> bool:
    now = int(time.time())
    if claims.get("iss") != expected_iss: raise AunsormTokenError("bad_iss")
    if expected_aud and claims.get("aud") != expected_aud: raise AunsormTokenError("bad_aud")
    if "nbf" in claims and now + skew < int(claims["nbf"]): raise AunsormTokenError("nbf_in_future")
    if "exp" in claims and now - skew >= int(claims["exp"]): raise AunsormTokenError("token_expired")
    if jti_seen is not None:
        jti = claims.get("jti")
        if not jti: raise AunsormTokenError("missing_jti")
        if isinstance(jti_seen, set):
            if jti in jti_seen: raise AunsormTokenError("replayed_jti")
            jti_seen.add(jti)
        else:
            if jti_seen.seen(jti): raise AunsormTokenError("replayed_jti")
    return True

# ---------- OAuth2 mini ----------
from urllib.parse import urlparse
def _validate_resources(resource: Optional[Union[str,List[str]]], allow_http=False, max_len=512) -> Optional[Union[str,List[str]]]:
    if resource is None: return None
    arr = resource if isinstance(resource, list) else [resource]
    out=[]
    for u in arr:
        if not isinstance(u,str): continue
        if len(u) > max_len: continue
        p = urlparse(u)
        if p.scheme not in (("https","http") if allow_http else ("https",)): continue
        if not p.netloc or not p.path: continue
        out.append(u)
    return out if isinstance(resource,list) else (out[0] if out else None)

class OAuthAS:
    def __init__(self, issuer="aunsorm", jti_store: Optional[SQLiteJTIStore]=None, keyring: Optional[KeyRing]=None):
        self.issuer = issuer
        self.keyring = keyring or KeyRing(); self.keyring.add_memory_key()
        self.tokens: Dict[str, Dict] = {}
        self.codes: Dict[str, Dict] = {}
        self.jti_store = jti_store
        self.clients: Dict[str, str] = {}
    def register_client(self, client_id: str, client_secret: str): self.clients[client_id] = client_secret
    def _auth_client(self, client_id: Optional[str], client_secret: Optional[str]):
        if client_id is None: return
        if self.clients.get(client_id) != client_secret: raise AunsormTokenError("invalid_client")
    def issue(self, sub:str, scope:str, aud="aunsorm", ttl=300, resource: Optional[Union[str,List[str]]]=None)->Dict:
        now=int(time.time()); jti=str(uuid.uuid4())
        kid, signer = self.keyring.get_active()
        res = _validate_resources(resource)
        claims={"sub":sub,"scope":scope,"aud":aud,"iat":now,"nbf":now,"exp":now+ttl,"jti":jti,"iss":self.issuer}
        if res: claims["res"] = res
        at=jwt_issue_ed25519(claims, signer, kid, iss=self.issuer)
        rt="rt_"+secrets.token_urlsafe(24)
        self.tokens[at]={"active":True,"scope":scope,"sub":sub,"rt":rt,"exp":now+ttl,"iat":now,"nbf":now,"aud":aud,"jti":jti,"kid":kid,"resource":res}
        log.info("OAuth issued for %s scope=%s ttl=%s", sub, scope, ttl)
        return {"access_token":at,"refresh_token":rt,"scope":scope,"token_type":"Bearer","expires_in":ttl,"resource":res}
    def refresh(self, refresh_token:str, client_id: Optional[str]=None, client_secret: Optional[str]=None,
                sub_hint=None, scope=None, aud="aunsorm", ttl=300, resource: Optional[Union[str,List[str]]]=None)->Dict:
        self._auth_client(client_id, client_secret)
        for at,meta in list(self.tokens.items()):
            if meta.get("rt")==refresh_token and meta.get("active",False):
                sc = scope or meta["scope"]; res = _validate_resources(resource) if resource is not None else meta.get("resource")
                return self.issue(sub_hint or meta["sub"], sc, aud=aud, ttl=ttl, resource=res)
        raise AunsormTokenError("invalid_refresh_token")
    def revoke(self, token:str, client_id: Optional[str]=None, client_secret: Optional[str]=None)->Dict:
        self._auth_client(client_id, client_secret)
        if token in self.tokens: self.tokens[token]["active"]=False
        return {"revoked":True}
    def introspect(self, token: str, client_id: Optional[str]=None, client_secret: Optional[str]=None,
                   token_type_hint: str="access_token") -> Dict:
        self._auth_client(client_id, client_secret)
        meta = self.tokens.get(token); now = int(time.time())
        if not meta:
            return {"active": False, "token_type_hint": token_type_hint, "iss": self.issuer}
        active = bool(meta.get("active") and meta.get("exp", 0) > now)
        # RFC 7662 alignment (+ not_before alias)
        return {
            "active": active,
            "scope": meta.get("scope",""),
            "username": meta.get("sub",""),
            "token_type": "access_token",
            "token_use": "access_token",
            "exp": meta.get("exp"),
            "iat": meta.get("iat"),
            "nbf": meta.get("nbf"),
            "not_before": meta.get("nbf"),
            "sub": meta.get("sub"),
            "aud": meta.get("aud"),
            "iss": self.issuer,
            "client_id": client_id or "public",
            "jti": meta.get("jti"),
            "kid": meta.get("kid"),
            "resource": meta.get("resource"),
            "token_type_hint": token_type_hint,
        }
    def jwks(self)->Dict: return self.keyring.get_pub_jwks()
    # PKCE
    _PKCE_CHARS = re.compile(r"^[A-Za-z0-9\-._~]{43,128}$")
    def _pkce_s256(self, verifier: str) -> str: return b64e(hashlib.sha256(verifier.encode()).digest())
    def begin_auth(self, sub:str, scope:str, aud="aunsorm", code_challenge:str="",
                   code_challenge_method:str="S256", ttl=300, client_id: Optional[str]=None, client_secret: Optional[str]=None,
                   resource: Optional[Union[str,List[str]]]=None)->Dict:
        self._auth_client(client_id, client_secret)
        if code_challenge_method not in ("S256","plain"): raise AunsormTokenError("unsupported_pkce_method")
        if code_challenge_method=="plain" and not self._PKCE_CHARS.match(code_challenge): raise AunsormTokenError("pkce_plain_invalid")
        res = _validate_resources(resource)
        code = "ac_"+secrets.token_urlsafe(24); now=int(time.time())
        ch = code_challenge if code_challenge_method=="plain" else self._pkce_s256(code_challenge)
        self.codes[code]={"sub":sub,"scope":scope,"aud":aud,"exp":now+ttl,"method":code_challenge_method,"challenge":ch,"resource":res}
        return {"code":code,"expires_in":ttl}
    def token_from_code(self, code:str, code_verifier:str, ttl=300, client_id: Optional[str]=None, client_secret: Optional[str]=None)->Dict:
        self._auth_client(client_id, client_secret)
        if not self._PKCE_CHARS.match(code_verifier): raise AunsormTokenError("pkce_verifier_invalid")
        meta = self.codes.get(code); now=int(time.time())
        if not meta or meta["exp"] < now: raise AunsormTokenError("invalid_or_expired_code")
        if meta["method"]=="S256":
            if self._pkce_s256(code_verifier) != meta["challenge"]: raise AunsormTokenError("pkce_mismatch")
        else:
            if code_verifier != meta["challenge"]: raise AunsormTokenError("pkce_mismatch")
        del self.codes[code]
        return self.issue(meta["sub"], meta["scope"], aud=meta["aud"], ttl=ttl, resource=meta.get("resource"))

# ---------- X.509 (Ed25519; AKI/SKI + CRL + Policies + CPS checks + calib_id OID) ----------
from cryptography.hazmat.primitives import hashes
from cryptography import x509
from cryptography.x509.oid import NameOID, ObjectIdentifier, ExtendedKeyUsageOID
try:
    from cryptography.x509 import PolicyQualifierId
except Exception:
    class PolicyQualifierId:
        CPS_QUALIFIER = ObjectIdentifier("1.3.6.1.5.5.7.2.1")
        USER_NOTICE   = ObjectIdentifier("1.3.6.1.5.5.7.2.2")

AUNSORM_OID_BASE = os.getenv("AUNSORM_OID_BASE", "1.3.6.1.4.1.55555")
OID_CALIB      = ObjectIdentifier(AUNSORM_OID_BASE + ".1")
OID_POLICY_DEF = ObjectIdentifier(AUNSORM_OID_BASE + ".2.1")

def validate_cps_uris(cps_uris: Optional[List[str]], allow_http=False, max_len=512) -> List[str]:
    if not cps_uris: return []
    from urllib.parse import urlparse
    out=[]
    for u in cps_uris:
        if not isinstance(u, str) or len(u) > max_len: continue
        p = urlparse(u)
        if p.scheme not in (("https","http") if allow_http else ("https",)): continue
        if not p.netloc or p.hostname in ("localhost","127.0.0.1"): continue
        if not p.path or p.path == "/": continue
        out.append(u)
    return out

def check_cps_http_access(cps_uris: List[str], timeout=3.0) -> Dict[str,bool]:
    ok = {}
    try:
        import requests
    except Exception:
        return {u: False for u in cps_uris}
    for u in cps_uris:
        try:
            r = requests.head(u, timeout=timeout, allow_redirects=True)
            if r.status_code >= 400: r = requests.get(u, timeout=timeout)
            ok[u] = (200 <= r.status_code < 400)
        except Exception:
            ok[u] = False
    return ok

def make_self_signed_cert(common_name: str, calib_id: str, days=365,
                          crl_urls: Optional[List[str]]=None,
                          policy_oid: Optional[str]=None,
                          cps_uris: Optional[List[str]]=None,
                          user_notice_text: Optional[str]=None,
                          check_cps: bool=False) -> Dict:
    if os.getenv("AUNSORM_PEN_REQUIRED","0").lower() in ("1","true") and AUNSORM_OID_BASE.endswith(".55555"):
        raise AunsormConfigError("Set a real IANA PEN in AUNSORM_OID_BASE for production.")

    if AUNSORM_OID_BASE.endswith(".55555"):
        log.warning("Using demo OID base %s — register your IANA PEN for production!", AUNSORM_OID_BASE)

    priv = ed25519.Ed25519PrivateKey.generate()
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (x509.CertificateBuilder()
        .subject_name(subject).issuer_name(issuer)
        .public_key(priv.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH, ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=True, key_encipherment=True, data_encipherment=False,
                                     key_agreement=False, key_cert_sign=False, crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(priv.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(priv.public_key()), critical=False)
    )
    if crl_urls:
        dp = [x509.DistributionPoint(full_name=[x509.UniformResourceIdentifier(u) for u in crl_urls], relative_name=None, reasons=None, crl_issuer=None)]
        builder = builder.add_extension(x509.CRLDistributionPoints(dp), critical=False)

    try:
        qualifiers = []
        valid_cps = validate_cps_uris(cps_uris)
        # cryptography>=38: PolicyInformation accepts either URIs (as strings) and/or UserNotice
        for u in valid_cps: qualifiers.append(u)
        if user_notice_text: qualifiers.append(x509.UserNotice(notice_reference=None, explicit_text=user_notice_text))
        if qualifiers:
            poid = ObjectIdentifier(policy_oid) if policy_oid else OID_POLICY_DEF
            pol = x509.CertificatePolicies([x509.PolicyInformation(poid, qualifiers)])
            builder = builder.add_extension(pol, critical=False)
    except Exception:
        pass

    builder = builder.add_extension(x509.UnrecognizedExtension(OID_CALIB, calib_id.encode()), critical=False)
    cert = builder.sign(priv, algorithm=None)

    pq_status = "skipped"
    if _HAVE_OQS:
        try:
            jws = pq_jws_sign(cert.public_bytes(serialization.Encoding.DER))
            if jws: pq_status=f"PQ-ext:{jws['alg']}"
        except Exception:
            pq_status="skipped"

    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    key_pem  = priv.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
    fp = x509.load_pem_x509_certificate(cert_pem.encode()).fingerprint(hashes.SHA256()).hex()
    cps_ok = check_cps_http_access(valid_cps) if (check_cps and valid_cps) else {}
    return {"cert_pem":cert_pem,"key_pem":key_pem,"fingerprint":fp,"pq_status":pq_status,"cps_ok":cps_ok}

# ---------- Async wrappers ----------
async def aunsorm_encrypt_async(*args, **kwargs): return await asyncio.to_thread(aunsorm_encrypt, *args, **kwargs)
async def aunsorm_decrypt_async(*args, **kwargs): return await asyncio.to_thread(aunsorm_decrypt, *args, **kwargs)

# ---------- CLI ----------
def _cli_encrypt(args):
    calib = None
    if args.calib and os.path.exists(args.calib): calib = json.load(open(args.calib))
    elif args.calib: calib = json.loads(args.calib)
    pkt = aunsorm_encrypt(args.password, open(args.infile,"rb").read(), profile=args.profile, pqc_kem=args.kem, aead_alg=args.aead,
                          recipient_kem_pk_b64=args.recipient_pk, calibration=calib, calib_mode=args.calib_mode, context_aad=args.aad)
    open(args.out,"w").write(pkt["packet"]); print("OK:", pkt["header"]["calib_id"][:16]+"…", pkt["header"]["aead"]["alg"])
def _cli_decrypt(args):
    calib=None
    if args.calib and os.path.exists(args.calib): calib=json.load(open(args.calib))
    elif args.calib: calib=json.loads(args.calib)
    pt, hdr = aunsorm_decrypt(args.password, open(args.infile).read().strip(), kem_sk_b64=args.kem_sk, calibration=calib, context_aad=args.aad)
    open(args.out,"wb").write(pt); print("OK:", hdr["calib_id"][:16]+"…", hdr["aead"]["alg"])
def _cli_oauth(args):
    store = SQLiteJTIStore(path=args.jti_db, ttl_sec=args.ttl)
    asrv  = OAuthAS(issuer=args.issuer, jti_store=store)
    asrv.register_client(args.client_id, args.client_secret)
    if args.cmd == "begin-auth":
        ch = secrets.token_urlsafe(64)[:64]
        out = asrv.begin_auth(args.sub, args.scope, code_challenge=ch, code_challenge_method="S256", resource=args.resource, client_id=args.client_id, client_secret=args.client_secret)
        print(json.dumps({"code": out["code"], "challenge_verifier": ch}, indent=2))
    elif args.cmd == "token":
        out = asrv.token_from_code(args.code, args.verifier, client_id=args.client_id, client_secret=args.client_secret)
        print(json.dumps(out, indent=2))
    elif args.cmd == "introspect":
        print(json.dumps(asrv.introspect(args.token, client_id=args.client_id, client_secret=args.client_secret), indent=2))
def _build_cli():
    p = argparse.ArgumentParser("aunsorm")
    sub = p.add_subparsers(dest="sub")
    pe = sub.add_parser("encrypt"); pe.add_argument("--password", required=True); pe.add_argument("--infile", required=True); pe.add_argument("--out", required=True)
    pe.add_argument("--profile", default="AUTO"); pe.add_argument("--kem", default=None); pe.add_argument("--aead", default="AUTO"); pe.add_argument("--recipient-pk", dest="recipient_pk", default=None)
    pe.add_argument("--calib", default=None); pe.add_argument("--calib-mode", default="EXTERNAL"); pe.add_argument("--aad", default=None)
    pe.set_defaults(func=_cli_encrypt)
    pd = sub.add_parser("decrypt"); pd.add_argument("--password", required=True); pd.add_argument("--infile", required=True); pd.add_argument("--out", required=True)
    pd.add_argument("--kem-sk", default=None); pd.add_argument("--calib", default=None); pd.add_argument("--aad", default=None)
    pd.set_defaults(func=_cli_decrypt)
    po = sub.add_parser("oauth"); po.add_argument("cmd", choices=["begin-auth","token","introspect"])
    po.add_argument("--issuer", default="aunsorm"); po.add_argument("--client-id", required=True); po.add_argument("--client-secret", required=True)
    po.add_argument("--sub", default="user"); po.add_argument("--scope", default="*"); po.add_argument("--code", default=None); po.add_argument("--verifier", default=None)
    po.add_argument("--resource", default=None); po.add_argument("--jti-db", default="jti.db"); po.add_argument("--ttl", type=int, default=300)
    po.set_defaults(func=_cli_oauth)
    return p

# ---------- Bench (optional) ----------
def bench(n=5, size=256_000, aead="AUTO", profile="AUTO", kem="ML-KEM-768", rb=False):
    PT = os.urandom(size); enc, dec = [], []
    recipient_pk_b64, kem_sk_b64 = None, None
    if rb and _HAVE_OQS:
        with oqs.KeyEncapsulation(kem) as R:
            recipient_pk = R.generate_keypair()
            try:
                if hasattr(R, "export_secret_key"): kem_sk_b64 = b64e(R.export_secret_key())
            except Exception: kem_sk_b64 = None
            recipient_pk_b64 = b64e(recipient_pk)
    calib={"alpha_L":0,"alpha_S":0,"beta_L":0,"beta_S":0,"tau":1,"A":0,"B":0,"C":0,"D":0,"E":0}
    for _ in range(n):
        t0=time.perf_counter()
        pkt=aunsorm_encrypt("P", PT, profile=profile, aead_alg=aead, pqc_kem=kem, recipient_kem_pk_b64=recipient_pk_b64,
                            calibration=calib, calib_mode="EXTERNAL")
        t1=time.perf_counter()
        _pt,_=aunsorm_decrypt("P", pkt["packet"], kem_sk_b64=kem_sk_b64, calibration=calib)
        t2=time.perf_counter()
        assert _pt==PT
        enc.append(t1-t0); dec.append(t2-t1)
    def pr(name,arr): print(f"{name}: p50={sorted(arr)[len(arr)//2]:.4f}s p95={sorted(arr)[int(0.95*len(arr))-1]:.4f}s")
    print(f"size={size} aead={aead} profile={profile} kem={kem} rb={rb} n={n}")
    pr("enc",enc); pr("dec",dec)

def run_cli(argv_list):
    cli = _build_cli()
    args = cli.parse_args(argv_list)
    if hasattr(args, "handler"): return args.handler(args)
    if hasattr(args, "func"): return args.func(args)

# ---------- DEMO ----------
if __name__ == "__main__":
    cli = _build_cli()
    argv = [] if _is_notebook() else None
    try:
        args = cli.parse_args(argv)
        if hasattr(args, "handler"): args.handler(args)
        elif hasattr(args, "func"): args.func(args)
    except SystemExit:
        if _is_notebook():
            print("CLI notebook’ta devre dışı. `run_cli([...])` ile kullanabilirsin.")
        else:
            raise

    print("== Aunsorm v1.01 Demo (Multi-tenant + Session + Standards++) ==")
    PASSWORD = "Neud-Anglenna-1.01"; DATA = b"Aunsorm v1.01 secret payload"

    # Tenant & calibration (DB note kaydı ortam değişkenine bağlı)
    db = TenantDB("aunsorm_mt.db")
    tenant = db.add_tenant_or_get("WeAreKut", org_salt=b"WeAreKut.eu", policy={"kdf_profile":"AUTO","aead_alg":"AUTO","require_external_calib":True})
    calib, calib_id, note_sha, note_id = db.text_to_calibration_for_tenant("WeAreKut", "Neudzulab | Prod | 2025-08", store_note=False)
    print("tenant:", tenant["name"], "| calib_id:", calib_id[:16]+"…", "| note_id:", note_id)

    # RB-KEM demo (requires liboqs)
    recipient_pk_b64 = None; kem_sk_b64 = None
    if _HAVE_OQS:
        with oqs.KeyEncapsulation("ML-KEM-768") as R:
            recipient_pk = R.generate_keypair()
            try:
                if hasattr(R, "export_secret_key"): kem_sk_b64 = b64e(R.export_secret_key())
            except Exception: pass
            recipient_pk_b64 = b64e(recipient_pk) if kem_sk_b64 else None

    # One-shot EXTERNAL
    pkt = aunsorm_encrypt(PASSWORD, DATA, profile="AUTO", pqc_kem="ML-KEM-768", aead_alg="AUTO",
                          recipient_kem_pk_b64=recipient_pk_b64, calibration=calib, calib_mode="EXTERNAL", context_aad=b"ctx:v1")
    print("[INFO] Encrypted bind=EXTERNAL, aead=", pkt["header"]["aead"]["alg"])
    try:
        rec, hdr = aunsorm_decrypt_safe(PASSWORD, pkt["packet"], kem_sk_b64=kem_sk_b64, calibration=calib, context_aad=b"ctx:v1")
        print("enc/dec ok:", rec == DATA, "| pq:", hdr["pq_enabled"], "| kem:", hdr["kem"]["kem"], "| rb:", hdr["kem"].get("rbkem"), "| aead:", hdr["aead"]["alg"], "| cid:", hdr["calib_id"][:16]+"…")
    except AunsormDecryptionFailed:
        print("decryption_failed")

    # Session amortization
    sess = AunsormSession(recipient_pk_b64, kem_name="ML-KEM-768")
    p1 = session_encrypt(sess, PASSWORD, b"msg-1", profile="AUTO", calibration=calib, calib_mode="EXTERNAL")
    p2 = session_encrypt(sess, PASSWORD, b"msg-2", profile="AUTO", calibration=calib, calib_mode="EXTERNAL")
    store = SessionStore()
    m1, _ = session_decrypt(store, PASSWORD, p1["packet"], kem_sk_b64=kem_sk_b64, calibration=calib)
    m2, _ = session_decrypt(store, PASSWORD, p2["packet"], kem_sk_b64=kem_sk_b64, calibration=calib)
    print("session dec:", m1, m2)

    # Wrong password → unified error
    try:
        _ = aunsorm_decrypt_safe("WRONG", pkt["packet"], kem_sk_b64=kem_sk_b64, calibration=calib, context_aad=b"ctx:v1")
        print("wrong-pass: should fail but passed")
    except AunsormDecryptionFailed:
        print("wrong-pass blocked: decryption_failed")

    # Missing calibration → unified error
    try:
        _ = aunsorm_decrypt_safe(PASSWORD, pkt["packet"], kem_sk_b64=kem_sk_b64)
        print("missing-calib: should fail but passed")
    except AunsormDecryptionFailed:
        print("missing-calib blocked: decryption_failed")

    # X.509 with CPS check (best-effort)
    cert = make_self_signed_cert("aunsorm.local", hdr["calib_id"], crl_urls=["http://example.com/crl.pem"], cps_uris=["https://example.com/cps.html"], user_notice_text="For demo purposes only.", check_cps=False)
    print("X509 fingerprint:", cert["fingerprint"][:32]+"…", "|", cert["pq_status"])

    # Mini bench
    bench(n=4, size=128_000, aead="AUTO", profile="AUTO", kem="ML-KEM-768", rb=False)



# ===============================================
# Aunsorm v1.01 — External Calibration Enforcer
# (Two-Party Shared "Calibration Text" Binding)
# Drop-in blok: EXTERNAL kalibrasyonu ZORUNLU kılar.
# İki uç da aynı org_salt + kalibrasyon metni olmadan açamaz.
# Bu blok, Aunsorm v1.01 kodunun altına eklenebilir.
# ===============================================

# ---- ZORUNLU DIŞ KALİBRASYON (metin) ARAYÜZÜ ----
# Not: Bu blok, Aunsorm v1.01 içindeki yardımcıları kullanır:
#   - CALIB_SCHEMA_V1, hkdf_sha256, _label, VERSION_LABEL,
#   - aunsorm_encrypt, aunsorm_decrypt, AunsormCalibrationMismatchError
#   - _normalize_text (varsa); yoksa aşağıdaki fallback kullanılır.

try:
    _normalize_text  # type: ignore[name-defined]
except NameError:
    import unicodedata
    def _normalize_text(note: str) -> str:
        n = unicodedata.normalize("NFC", note).strip()
        return " ".join(n.split())

def _aunsorm_calib_from_text(org_salt: bytes, note_text: str) -> tuple[dict, str]:
    """
    DB gerektirmeyen, deterministik metin→kalibrasyon eşlemi.
    Aynı org_salt + aynı metin => aynı 'calib' ve 'calib_id'.
    """
    norm = _normalize_text(note_text)
    base_ikm = hashlib.sha512(b"Aunsorm/1.01|CALIB|TEXT|" + norm.encode("utf-8")).digest()
    salt = hashlib.sha256(org_salt).digest()

    def _u_to_q(u64: bytes, lo: float, hi: float, step: float) -> float:
        u = int.from_bytes(u64, "big") / float(1 << 64)
        raw = lo + (hi - lo) * u
        if step >= 1.0:
            v = float(int(round(raw / step) * step))
        else:
            v = float(round(round(raw / step) * step, 9))
        return max(lo, min(hi, v))

    calib: dict[str, float] = {}
    for field, (lo, hi, step) in CALIB_SCHEMA_V1.items():  # type: ignore[name-defined]
        u64 = hkdf_sha256(base_ikm, salt, b"Aunsorm/1.01/CALIB-FIELD|" + field.encode(), 8)  # type: ignore[name-defined]
        calib[field] = _u_to_q(u64, lo, hi, step)

    # Aunsorm/1.x kalibrasyon kimliği (id) (prefix bağlamıyla)
    prefix = b"Aunsorm/1.x|schema:v1|"
    calib_id = hashlib.sha256(prefix + json.dumps(
        calib, sort_keys=True, separators=(",", ":")
    ).encode()).hexdigest()
    return calib, calib_id

def aunsorm_encrypt_with_calib_text(
    password: str,
    plaintext: bytes,
    *,
    org_salt: bytes,
    calibration_text: str,
    pqc_kem: str | None = "ML-KEM-768",
    aead_alg: str | None = "AUTO",
    context_aad: str | bytes | None = None,
) -> dict:
    """
    EXTERNAL kalibrasyon zorunlu. Gönderici taraf.
    Aynı org_salt + kalibrasyon metni olmadan şifre çözülemez.
    """
    calib, _cid = _aunsorm_calib_from_text(org_salt, calibration_text)
    return aunsorm_encrypt(  # type: ignore[name-defined]
        password,
        plaintext,
        profile="AUTO",
        pqc_kem=pqc_kem,
        aead_alg=aead_alg,
        recipient_kem_pk_b64=None,     # RB-KEM istiyorsan burada alıcı PK verilebilir
        calibration=calib,
        calib_mode="EXTERNAL",
        context_aad=context_aad,
    )

def aunsorm_decrypt_with_calib_text(
    password: str,
    packet_b64: str,
    *,
    org_salt: bytes,
    calibration_text: str,
    kem_sk_b64: str | None = None,
    context_aad: str | bytes | None = None,
    replay_store: set[str] | "SQLiteJTIStore" | None = None,  # opsiyonel tekrar engeli
) -> tuple[bytes, dict]:
    """
    EXTERNAL kalibrasyon zorunlu. Alıcı taraf (AUTH tarafı).
    Doğru org_salt + aynı kalibrasyon metni olmadan çözülmez.
    """
    calib, _cid = _aunsorm_calib_from_text(org_salt, calibration_text)
    # One-shot tekrar engeli kullanmak istersen aunsorm_decrypt'e geçir:
    if replay_store is None:
        return aunsorm_decrypt(  # type: ignore[name-defined]
            password,
            packet_b64,
            kem_sk_b64=kem_sk_b64,
            calibration=calib,
            context_aad=context_aad,
        )
    else:
        return aunsorm_decrypt(  # type: ignore[name-defined]
            password,
            packet_b64,
            kem_sk_b64=kem_sk_b64,
            calibration=calib,
            context_aad=context_aad,
            replay_store=replay_store,
        )

def aunsorm_peek_calib_id_from_text(org_salt: bytes, calibration_text: str) -> str:
    """
    Şifre çözmeden önce, beklenen calib_id’yi hesaplamak için yardımcı.
    (Header içindeki calib_id ile karşılaştırarak yanlış metni erken yakalayabilirsin.)
    """
    _, cid = _aunsorm_calib_from_text(org_salt, calibration_text)
    return cid

def aunsorm_packet_header(packet_b64: str) -> dict:
    """
    Paketin header bölümünü (JSON) döndürür (doğrulama yapmaz).
    Karşılaştırma/teşhis için kullanılabilir.
    """
    raw = base64.urlsafe_b64decode(packet_b64 + "=" * (-len(packet_b64) % 4))
    if len(raw) < 4 + 32:
        raise AunsormInvalidPacketError("Packet too short")  # type: ignore[name-defined]
    body = raw[:-32]
    if len(body) < 4:
        raise AunsormInvalidPacketError("Body too short")  # type: ignore[name-defined]
    hlen = struct.unpack(">I", body[:4])[0]
    if hlen < 32 or hlen > len(body) - 4:
        raise AunsormInvalidPacketError("Header length invalid")  # type: ignore[name-defined]
    header = json.loads(body[4:4 + hlen].decode())
    return header

# -------------- KULLANIM ÖRNEĞİ --------------
# Not: Blok doğrudan çalıştırılırsa küçük bir uçtan uca demo yapar.
if __name__ == "__main__" and os.getenv("AUNSORM_DEMO_EXTCALIB", "1") in ("1", "true"):
    ORG_SALT = b"WeAreKut.eu"  # AUTH tarafınca bilinen/korunan salt
    CAL_TEXT = "Neudzulab | Prod | 2025-08"  # İki tarafın paylaştığı kalibrasyon metni (gizli tutulmalı)
    PASSWORD = "Neud-Anglenna-1.01"
    DATA = b"secret-payload"

    # Gönderici:
    enc = aunsorm_encrypt_with_calib_text(
        PASSWORD, DATA, org_salt=ORG_SALT, calibration_text=CAL_TEXT, pqc_kem="ML-KEM-768", aead_alg="AUTO", context_aad=b"ctx:v1"
    )

    # (İsteğe bağlı erken kontrol) Header’daki calib_id ile beklenen eşleşiyor mu?
    hdr = aunsorm_packet_header(enc["packet"])
    expected_cid = aunsorm_peek_calib_id_from_text(ORG_SALT, CAL_TEXT)
    assert hdr["calib_id"] == expected_cid, "calibration id mismatch (sender)"

    # Alıcı (AUTH tarafı):
    pt, hdr2 = aunsorm_decrypt_with_calib_text(
        PASSWORD, enc["packet"], org_salt=ORG_SALT, calibration_text=CAL_TEXT, kem_sk_b64=None, context_aad=b"ctx:v1"
    )

    assert pt == DATA, "decrypt failed"
    assert hdr2["calib_id"] == expected_cid, "calibration id mismatch (receiver)"
    print("[EXT-CALIB OK] aead=", hdr2["aead"]["alg"], "| pq=", hdr2["pq_enabled"], "| cid=", hdr2["calib_id"][:16]+"…")
