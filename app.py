# app.py (single-file RedactPro)
import streamlit as st
import fitz, io, tempfile, cv2, numpy as np
from presidio_analyzer import AnalyzerEngine
from moviepy.editor import VideoFileClip
from pydub import AudioSegment
from pydub.generators import Sine
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from PIL import Image
import piexif
from mutagen import File as MutagenFile
import os, re, json, hashlib, datetime

# ---------------- PAGE CONFIG ----------------
st.set_page_config(page_title="🔒 RedactPro", layout="wide")

# ---------------- GLOBAL DARK THEME ----------------
st.markdown("""
<style>

/* Base */
.stApp {
    background-color: #020617;
    color: #f8fafc;
    font-size: 17px;
}

/* Text */
h1,h2,h3,h4,h5,h6,p,label,span,div {
    color: #f8fafc !important;
}

/* Inputs */
input, textarea, select {
    background-color: #020617 !important;
    color: #f8fafc !important;
    border-radius: 6px !important;
    border: 1px solid #334155 !important;
}

/* Radio / Checkbox / Multiselect text */
.stRadio label, .stCheckbox label, .stMultiSelect label {
    color: #f8fafc !important;
}

/* Buttons */
button {
    background-color: #0f172a !important;
    color: #f8fafc !important;
    border-radius: 6px !important;
    font-weight: 600;
}
button:hover {
    background-color: #1e293b !important;
}

/* Upload box – smaller */
section[data-testid="stFileUploader"] {
    max-width: 380px;
    padding: 6px;
}

/* Tabs */
button[data-baseweb="tab"] {
    color: #f8fafc !important;
}

/* Sidebar */
section[data-testid="stSidebar"] {
    background-color: #020617;
}

/* Top toolbar icons */
header[data-testid="stHeader"] {
    background: #020617;
}
header[data-testid="stHeader"] svg {
    fill: #f8fafc !important;
}

/* Info / Success / Error */
div[data-testid="stAlert"] {
    background-color: #020617;
    border: 1px solid #334155;
}

</style>
""", unsafe_allow_html=True)

# ---------------- TITLE ----------------
st.title("🔒 REDACTPRO — Blockchain-Based Secure Data Redaction & Audit")

# ---------------- OPTIONAL IMPORTS ----------------
try:
    from streamlit_drawable_canvas import st_canvas
    CANVAS_AVAILABLE = True
except:
    CANVAS_AVAILABLE = False

try:
    import pytesseract
    OCR_AVAILABLE = True
except:
    OCR_AVAILABLE = False

# ---------------- UTILITIES ----------------
def encrypt_bytes(data_bytes, key_bytes):
    cipher = AES.new(key_bytes, AES.MODE_CBC)
    return cipher.iv + cipher.encrypt(pad(data_bytes, AES.block_size))

def decrypt_bytes(enc_bytes, key_bytes):
    iv, ct = enc_bytes[:16], enc_bytes[16:]
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), AES.block_size)

# ---------------- LEDGER ----------------
LEDGER_FILE = "ledger.json"

def compute_hash(block):
    return hashlib.sha256(json.dumps(block, sort_keys=True).encode()).hexdigest()

def ensure_ledger():
    if not os.path.exists(LEDGER_FILE):
        g = {"index":0,"prev":"0"*64,"data":"Genesis","time":str(datetime.datetime.utcnow())}
        g["hash"] = compute_hash(g)
        json.dump([g], open(LEDGER_FILE,"w"), indent=4)

def add_block(action):
    ensure_ledger()
    ledger = json.load(open(LEDGER_FILE))
    prev = ledger[-1]["hash"]
    blk = {"index":len(ledger),"prev":prev,"data":action,"time":str(datetime.datetime.utcnow())}
    blk["hash"] = compute_hash(blk)
    ledger.append(blk)
    json.dump(ledger, open(LEDGER_FILE,"w"), indent=4)

def verify_ledger():
    ensure_ledger()
    ledger = json.load(open(LEDGER_FILE))
    for i in range(1,len(ledger)):
        if ledger[i]["prev"] != ledger[i-1]["hash"]:
            return "❌ Ledger Tampered"
    return "✅ Ledger Valid"

# ---------------- ANALYZER ----------------
analyzer = AnalyzerEngine()

# ---------------- TABS ----------------
tabs = st.tabs(["📁 Multi Redaction", "👥 Role-Based Redaction", "🔓 Decrypt"])

# ================= MULTI =================
with tabs[0]:
    st.subheader("📁 Multi Redaction")
    mode = st.radio("Mode", ["PII Automatic", "Custom", "Manual"])

    file = st.file_uploader("Upload TXT or PDF", type=["txt","pdf"])
    encrypt = st.checkbox("Encrypt Output (AES)")

    if file and st.button("Redact"):
        txt = file.getvalue().decode("utf-8", errors="ignore")
        res = analyzer.analyze(txt, language="en")
        for r in sorted(res, key=lambda x:x.start, reverse=True):
            txt = txt[:r.start] + "█"*len(txt[r.start:r.end]) + txt[r.end:]
        out = txt.encode()

        if encrypt:
            key = get_random_bytes(16)
            out = encrypt_bytes(out, key)
            st.code(f"AES KEY: {key.hex()}")

        add_block("Multi Redaction")
        st.download_button("⬇️ Download", out, file_name="redacted.txt")

    if st.button("Verify Ledger"):
        st.success(verify_ledger())

# ================= ROLE =================
with tabs[1]:
    st.subheader("👥 Role-Based Redaction")

    role = st.selectbox("Select Role", ["admin","doctor","intern","guest"])
    file = st.file_uploader("Upload TXT", type=["txt"])

    if file and st.button("Apply Role Redaction"):
        text = file.getvalue().decode("utf-8", errors="ignore")
        res = analyzer.analyze(text, language="en")
        for r in sorted(res, key=lambda x:x.start, reverse=True):
            if role != "admin":
                text = text[:r.start] + "█"*len(text[r.start:r.end]) + text[r.end:]
        add_block(f"Role Redaction {role}")
        st.download_button("⬇️ Download", text.encode(), file_name="role_redacted.txt")

# ================= DECRYPT =================
with tabs[2]:
    st.subheader("🔓 Decrypt AES File")
    f = st.file_uploader("Encrypted file")
    k = st.text_input("AES Key (hex)")

    if f and k and st.button("Decrypt"):
        try:
            dec = decrypt_bytes(f.getvalue(), bytes.fromhex(k))
            st.text_area("Output", dec.decode(errors="ignore"), height=300)
        except:
            st.error("Invalid key or file")

# ---------------- END ----------------
