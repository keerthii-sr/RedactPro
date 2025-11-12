# app.py
import streamlit as st
import fitz
import io
import tempfile
import cv2
import numpy as np
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
import os, re, json, hashlib, datetime, time

# ---------------- Optional OCR ---------------- #
try:
    import pytesseract
    OCR_AVAILABLE = True
except Exception:
    OCR_AVAILABLE = False

# ---------------- AES utilities ---------------- #
def encrypt_bytes(data_bytes, key_bytes):
    cipher = AES.new(key_bytes, AES.MODE_CBC)
    return cipher.iv + cipher.encrypt(pad(data_bytes, AES.block_size))

def decrypt_bytes(enc_bytes, key_bytes):
    iv, ct = enc_bytes[:16], enc_bytes[16:]
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), AES.block_size)

# ---------------- Metadata cleaning ---------------- #
def clean_metadata(file_path, file_type):
    try:
        ft = file_type.lower()
        if ft in ("jpg","jpeg","png"):
            try:
                piexif.remove(file_path)
            except Exception:
                img = Image.open(file_path)
                img_no_meta = Image.new(img.mode, img.size)
                img_no_meta.putdata(list(img.getdata()))
                img_no_meta.save(file_path)
        elif ft in ("mp3","wav","mp4","mkv","avi"):
            try:
                m = MutagenFile(file_path)
                if m:
                    try:
                        m.delete()
                        m.save()
                    except Exception:
                        pass
            except Exception:
                pass
        elif ft == "pdf":
            doc = fitz.open(file_path)
            doc.set_metadata({})
            cleaned = file_path.replace(".pdf","_cleaned.pdf")
            doc.save(cleaned); doc.close()
            return cleaned
    except Exception:
        pass
    return file_path

# ---------------- Blockchain ledger ---------------- #
LEDGER_DIR = os.path.join(os.getcwd(), "redactpro_auth")
os.makedirs(LEDGER_DIR, exist_ok=True)
LEDGER_FILE = os.path.join(LEDGER_DIR, "ledger.json")

def compute_hash(record):
    s = json.dumps(record, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(s.encode()).hexdigest()

def ensure_ledger_exists():
    if not os.path.exists(LEDGER_FILE):
        genesis = {
            "timestamp": datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
            "user": "system",
            "role": "root",
            "action": "Genesis",
            "file_hash": "0"*64,
            "prev_hash": "0"*64
        }
        genesis["current_hash"] = compute_hash(genesis)
        with open(LEDGER_FILE, "w") as f:
            json.dump([genesis], f, indent=4)

def load_ledger():
    ensure_ledger_exists()
    with open(LEDGER_FILE, "r") as f:
        return json.load(f)

def append_block(user, role, action, file_hash):
    ledger = load_ledger()
    prev_hash = ledger[-1]["current_hash"]
    block = {
        "timestamp": datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
        "user": user,
        "role": role,
        "action": action,
        "file_hash": file_hash,
        "prev_hash": prev_hash
    }
    block["current_hash"] = compute_hash(block)
    ledger.append(block)
    with open(LEDGER_FILE, "w") as f:
        json.dump(ledger, f, indent=4)

def verify_ledger():
    ensure_ledger_exists()
    ledger = load_ledger()
    for i in range(1, len(ledger)):
        prev, cur = ledger[i-1], ledger[i]
        if cur.get("prev_hash") != prev.get("current_hash"):
            return f"❌ Tampering detected between block {i-1} and {i}"
        recomputed = compute_hash({
            "timestamp": cur.get("timestamp"),
            "user": cur.get("user"),
            "role": cur.get("role"),
            "action": cur.get("action"),
            "file_hash": cur.get("file_hash"),
            "prev_hash": cur.get("prev_hash")
        })
        if recomputed != cur.get("current_hash"):
            return f"❌ Tampering detected at block {i}"
    return "✅ Ledger valid — no tampering detected"

# ---------------- OCR helpers (improved) ---------------- #
def detect_text_regions(img, min_confidence=20, edge_margin_ratio=0.1, force_edge=False):
    """
    Returns list of rects (x,y,w,h) that are likely watermark/text.
    Heuristics:
      - recognized OCR text with confidence >= min_confidence AND keyword match
      - OR any recognized text near image edges (if force_edge True or near border)
      - also checks for timestamp patterns and common watermark keywords
    """
    rects = []
    if not OCR_AVAILABLE:
        return rects
    try:
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        # use Tesseract to get detailed data incl confidence
        data = pytesseract.image_to_data(gray, output_type=pytesseract.Output.DICT)
        n = len(data['text'])
        h_img, w_img = gray.shape
        edge_margin_x = int(w_img * edge_margin_ratio)
        edge_margin_y = int(h_img * edge_margin_ratio)

        # common watermark keywords / patterns
        watermark_keywords = [
            "shot", "shoton", "shot_on", "camera", "ai", "vivo", "oppo", "samsung",
            "xiaomi", "iphone", "date", "time", "galaxy", "tab", "powered by",
            "timestamp", "utc"
        ]
        # regex patterns for timestamps / phone-like small texts etc.
        timestamp_re = re.compile(r"\b(20\d{2}[-/]\d{1,2}[-/]\d{1,2})\b|\b(\d{1,2}:\d{2}(:\d{2})?)\b")
        small_text_area_ratio = 0.12  # heuristic

        for i in range(n):
            txt = data['text'][i].strip()
            if not txt:
                continue
            conf_str = data.get('conf', [])[i] if 'conf' in data else '-1'
            try:
                conf = int(float(conf_str))
            except Exception:
                conf = -1
            left, top, width, height = data['left'][i], data['top'][i], data['width'][i], data['height'][i]
            low = txt.lower()

            near_edge = (left < edge_margin_x) or (top < edge_margin_y) or ((left + width) > (w_img - edge_margin_x)) or ((top + height) > (h_img - edge_margin_y))
            small_box = (height < h_img * small_text_area_ratio) and (width < w_img * 0.6)

            # keyword match & decent confidence
            is_kw = any(k in low for k in watermark_keywords)
            is_ts = bool(timestamp_re.search(txt))

            # decide if candidate
            candidate = False
            if is_kw and conf >= min_confidence:
                candidate = True
            elif is_ts:
                candidate = True
            elif (near_edge and (conf >= min_confidence or force_edge)):
                # near edge -> consider it a watermark even if confidence low (if force_edge)
                candidate = True
            elif small_box and conf >= min_confidence and any(ch.isdigit() for ch in txt):
                candidate = True

            if candidate:
                pad_px = max(4, int(min(width, height) * 0.25))
                x0 = max(0, left - pad_px)
                y0 = max(0, top - pad_px)
                x1 = min(w_img, left + width + pad_px)
                y1 = min(h_img, top + height + pad_px)
                rects.append((x0, y0, x1 - x0, y1 - y0))

    except Exception:
        pass
    return rects

def blur_regions(img, rects, ksize=(99,99)):
    out = img.copy()
    for (x,y,w,h) in rects:
        roi = out[y:y+h, x:x+w]
        if roi.size == 0: continue
        out[y:y+h, x:x+w] = cv2.GaussianBlur(roi, ksize, 30)
    return out

# ---------------- Presidio ---------------- #
analyzer = AnalyzerEngine()

def redact_text_presidio(text, selected_entity_types=None, role="guest"):
    results = analyzer.analyze(text=text, language="en")
    for r in sorted(results, key=lambda x: x.start, reverse=True):
        ent_type = getattr(r, "entity_type", None)
        if selected_entity_types and ent_type not in selected_entity_types:
            continue
        start, end = r.start, r.end
        ent = text[start:end]
        if role == "admin":
            continue
        elif role in ("doctor","professor"):
            replacement = "█" * max(4, len(ent)//2)
        else:
            replacement = "█" * max(4, len(ent))
        text = text[:start] + replacement + text[end:]
    return text

# ---------------- UI ---------------- #
st.set_page_config(page_title="🔒 RedactPro", layout="wide")
st.title("🔒 REDACTPRO — A BLOCKCHAIN-BASED SECURE DATA REDACTION AND  AUDIT SYSTEM")

# Top-level tabs
tabs = st.tabs(["📁 Multi Redaction", "👥 Role-Based Redaction", "🔓 Decrypt Encrypted"])

# ---------- MULTI REDACTION ----------
with tabs[0]:
    st.subheader("📁 Multi Redaction")
    mr_tabs = st.tabs(["📄 File (TXT / PDF)", "🖼️ Image", "🎥 Video", "🎵 Audio"])

    # ---- File (TXT/PDF) ----
    with mr_tabs[0]:
        st.markdown("**Text & PDF Redaction (with AES + Blockchain)**")
        # Mode choice: keep PII automatic AND add custom checkbox mode
        mr_mode = st.radio("Mode:", ["PII (automatic)", "Custom selection (checkboxes)"], key="mr_mode_radio")

        # If custom mode, show checkbox list (same entity types as role-based)
        ENTITY_CHOICES = [
            ("PERSON", "PERSON"),
            ("EMAIL_ADDRESS", "EMAIL_ADDRESS"),
            ("PHONE_NUMBER", "PHONE_NUMBER"),
            ("CREDIT_CARD", "CREDIT_CARD"),
            ("LOCATION", "LOCATION"),
            ("DATE_TIME", "DATE_TIME"),
            ("IP_ADDRESS", "IP_ADDRESS")
        ]
        if mr_mode == "Custom selection (checkboxes)":
            labels = [lab for lab,_ in ENTITY_CHOICES]
            defaults = ["PERSON","EMAIL_ADDRESS","PHONE_NUMBER"]
            chosen_labels = st.multiselect("Select types to redact:", labels, default=[l for l in labels if l in defaults], key="mr_entity_select")
            selected_entities = [val for (lab,val) in ENTITY_CHOICES if lab in chosen_labels]
        else:
            selected_entities = None  # means full PII automatic

        mr_uploaded = st.file_uploader("Upload TXT or PDF", type=["txt","pdf"], key="mr_file_upload")
        mr_encrypt = st.checkbox("Encrypt after redaction (AES)", key="mr_encrypt")

        if mr_uploaded and st.button("Redact File (Multi)", key="mr_file_go"):
            suffix = mr_uploaded.name.split(".")[-1].lower()
            tfile = tempfile.NamedTemporaryFile(delete=False, suffix=f".{suffix}")
            tfile.write(mr_uploaded.getbuffer()); tfile.close()
            cleaned_path = clean_metadata(tfile.name, suffix)

            if suffix == "txt":
                with open(cleaned_path, "r", encoding="utf-8", errors="ignore") as f:
                    text = f.read()
                if mr_mode == "PII (automatic)":
                    text = redact_text_presidio(text, selected_entity_types=None)
                else:
                    text = redact_text_presidio(text, selected_entity_types=selected_entities)
                out_bytes = text.encode("utf-8")
                if mr_encrypt:
                    key = get_random_bytes(16)
                    enc = encrypt_bytes(out_bytes, key)
                    st.code(f"AES key (hex): {key.hex()}")
                    st.download_button("⬇️ Download Encrypted TXT", enc, file_name="redacted_enc.txt", key="mr_dl_enc_txt")
                    file_hash = hashlib.sha256(enc).hexdigest()
                else:
                    st.download_button("⬇️ Download Redacted TXT", out_bytes, file_name="redacted.txt", key="mr_dl_txt")
                    file_hash = hashlib.sha256(out_bytes).hexdigest()
                append_block("guest", "multi", "Text Redaction", file_hash)
                st.success("✅ Text redacted and recorded to ledger (multi).")

            elif suffix == "pdf":
                doc = fitz.open(cleaned_path)
                for page in doc:
                    text = page.get_text()
                    # choose entity set depending on mode
                    if mr_mode == "PII (automatic)":
                        results = analyzer.analyze(text=text, language="en")
                        for r in results:
                            ent = text[r.start:r.end]
                            if ent.strip():
                                for rect in page.search_for(ent):
                                    page.add_redact_annot(rect, fill=(0,0,0))
                    else:
                        # custom selection: only redact selected entities
                        results = analyzer.analyze(text=text, language="en")
                        for r in results:
                            ent_type = getattr(r, "entity_type", None)
                            if selected_entities and ent_type not in selected_entities:
                                continue
                            ent = text[r.start:r.end]
                            if ent.strip():
                                for rect in page.search_for(ent):
                                    page.add_redact_annot(rect, fill=(0,0,0))
                    page.apply_redactions()
                out = io.BytesIO(); doc.save(out)
                pdf_bytes = out.getvalue()
                if mr_encrypt:
                    key = get_random_bytes(16)
                    enc = encrypt_bytes(pdf_bytes, key)
                    st.code(f"AES key (hex): {key.hex()}")
                    st.download_button("⬇️ Download Encrypted PDF", enc, file_name="redacted_enc.pdf", key="mr_dl_enc_pdf")
                    file_hash = hashlib.sha256(enc).hexdigest()
                else:
                    st.download_button("⬇️ Download Redacted PDF", pdf_bytes, file_name="redacted.pdf", key="mr_dl_pdf")
                    file_hash = hashlib.sha256(pdf_bytes).hexdigest()
                append_block("guest", "multi", "PDF Redaction", file_hash)
                st.success("✅ PDF redacted and recorded to ledger (multi).")

        st.markdown("---")
        st.markdown("### 📜 Verify Blockchain Ledger (Multi Text/PDF)")
        if st.button("Verify Ledger Integrity (Multi)", key="verify_multi"):
            res = verify_ledger()
            if res.startswith("✅"): st.success(res)
            else: st.error(res)

    # ---- Image ----
    with mr_tabs[1]:
        st.markdown("**Image Redaction (body parts + watermark blur)**")
        img_file = st.file_uploader("Upload Image (jpg/png)", type=["jpg","jpeg","png"], key="mr_img_upload")
        # force edge option for aggressive watermark blurring
        force_edge = st.checkbox("Force Edge Watermark Blur (aggressive)", key="mr_force_edge")
        parts_img = st.multiselect("Select parts to blur", ["Face","Eyes","Nose","Mouth","Full body"], key="mr_image_parts")
        if img_file and st.button("Redact Image (Multi)", key="mr_img_go"):
            _, ext = os.path.splitext(img_file.name)
            tpath = tempfile.NamedTemporaryFile(delete=False, suffix=ext).name
            with open(tpath, "wb") as f:
                f.write(img_file.getbuffer())
            cleaned = clean_metadata(tpath, ext.replace(".","").lower())
            file_bytes = np.asarray(bytearray(open(cleaned,"rb").read()), dtype=np.uint8)
            img = cv2.imdecode(file_bytes, cv2.IMREAD_COLOR)
            if img is None:
                st.error("Failed to read image.")
            else:
                # detect watermark candidates with improved heuristics
                rects = detect_text_regions(img, min_confidence=20, edge_margin_ratio=0.12, force_edge=force_edge)
                if rects:
                    img = blur_regions(img, rects, ksize=(51,51))
                gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
                cascades = {
                    "Face": cv2.CascadeClassifier(cv2.data.haarcascades + "haarcascade_frontalface_default.xml"),
                    "Eyes": cv2.CascadeClassifier(cv2.data.haarcascades + "haarcascade_eye.xml"),
                    "Nose": cv2.CascadeClassifier(cv2.data.haarcascades + "haarcascade_mcs_nose.xml"),
                    "Mouth": cv2.CascadeClassifier(cv2.data.haarcascades + "haarcascade_smile.xml")
                }
                if "Full body" in parts_img:
                    img = cv2.GaussianBlur(img, (99,99), 30)
                else:
                    for part in parts_img:
                        if part in cascades:
                            objs = cascades[part].detectMultiScale(gray, 1.3, 5)
                            for (x,y,w,h) in objs:
                                roi = img[y:y+h, x:x+w]
                                img[y:y+h, x:x+w] = cv2.GaussianBlur(roi, (99,99), 30)
                buf = cv2.imencode(".png", img)[1].tobytes()
                st.image(cv2.cvtColor(img, cv2.COLOR_BGR2RGB))
                st.download_button("⬇️ Download Redacted Image", buf, file_name="redacted_image.png", key="mr_img_dl")
                st.success("🖼️ Image redaction done (watermarks and selected parts blurred).")

    # ---- Video ----
    with mr_tabs[2]:
        st.markdown("**Video Redaction (body parts + watermark blur)**")
        vid_file = st.file_uploader("Upload Video (mp4/avi)", type=["mp4","avi"], key="mr_vid_upload")
        force_edge_vid = st.checkbox("Force Edge Watermark Blur (video)", key="mr_force_edge_vid")
        parts_vid = st.multiselect("Select parts to blur", ["Face","Eyes","Nose","Mouth","Full body"], key="mr_video_parts")
        if vid_file and st.button("Redact Video (Multi)", key="mr_vid_go"):
            tfile = tempfile.NamedTemporaryFile(delete=False, suffix=os.path.splitext(vid_file.name)[1])
            tfile.write(vid_file.getbuffer()); tfile.close()
            cleaned_video = clean_metadata(tfile.name, "mp4")
            clip = VideoFileClip(cleaned_video)
            cascades = {
                "Face": cv2.CascadeClassifier(cv2.data.haarcascades + "haarcascade_frontalface_default.xml"),
                "Eyes": cv2.CascadeClassifier(cv2.data.haarcascades + "haarcascade_eye.xml"),
                "Nose": cv2.CascadeClassifier(cv2.data.haarcascades + "haarcascade_mcs_nose.xml"),
                "Mouth": cv2.CascadeClassifier(cv2.data.haarcascades + "haarcascade_smile.xml")
            }

            # build watermark rects from first frame (more aggressive if forced)
            try:
                sample = clip.get_frame(0)
                sample_bgr = cv2.cvtColor(sample.astype('uint8'), cv2.COLOR_RGB2BGR)
                watermark_rects = detect_text_regions(sample_bgr, min_confidence=18, edge_margin_ratio=0.12, force_edge=force_edge_vid)
            except Exception:
                watermark_rects = []

            def process_frame(frame):
                frame_bgr = cv2.cvtColor(frame.astype('uint8'), cv2.COLOR_RGB2BGR)
                if watermark_rects:
                    frame_bgr = blur_regions(frame_bgr, watermark_rects, ksize=(51,51))
                if "Full body" in parts_vid:
                    return cv2.cvtColor(cv2.GaussianBlur(frame_bgr, (99,99), 30), cv2.COLOR_BGR2RGB)
                gray = cv2.cvtColor(frame_bgr, cv2.COLOR_BGR2GRAY)
                for part in parts_vid:
                    if part in cascades:
                        objs = cascades[part].detectMultiScale(gray, 1.3, 5)
                        for (x,y,w,h) in objs:
                            frame_bgr[y:y+h, x:x+w] = cv2.GaussianBlur(frame_bgr[y:y+h, x:x+w], (99,99), 30)
                return cv2.cvtColor(frame_bgr, cv2.COLOR_BGR2RGB)

            redacted = clip.fl_image(process_frame)
            out_path = tempfile.NamedTemporaryFile(delete=False, suffix=".mp4").name
            redacted.write_videofile(out_path, codec="libx264", audio_codec="aac", ffmpeg_params=["-map_metadata", "-1"])
            st.video(out_path)
            with open(out_path, "rb") as f:
                st.download_button("⬇️ Download Redacted Video", f.read(), file_name="redacted_video.mp4", key="mr_vid_dl")
            st.success("🎥 Video redaction done (watermarks and selected parts blurred).")

    # ---- Audio ----
    with mr_tabs[3]:
        st.markdown("**Audio Redaction (Beep Replacement)**")
        audio_file = st.file_uploader("Upload Audio (mp3/wav)", type=["mp3","wav"], key="mr_audio_upload")
        seconds = st.text_input("Seconds to beep (e.g., 5-10,15-20)", key="mr_audio_secs")
        if audio_file and st.button("Redact Audio (Multi)", key="mr_audio_go"):
            tpath = tempfile.NamedTemporaryFile(delete=False, suffix=os.path.splitext(audio_file.name)[1]).name
            with open(tpath, "wb") as f:
                f.write(audio_file.getbuffer())
            clean_metadata(tpath, os.path.splitext(tpath)[1].replace(".",""))
            sound = AudioSegment.from_file(tpath)
            ranges = []
            if seconds:
                for r in seconds.split(","):
                    try:
                        s,e = map(int, r.split("-"))
                        ranges.append((s*1000, e*1000))
                    except Exception:
                        pass
            for (s,e) in ranges:
                beep = Sine(1000).to_audio_segment(duration=(e-s))
                sound = sound[:s] + beep + sound[e:]
            outp = tempfile.NamedTemporaryFile(delete=False, suffix=".wav").name
            sound.export(outp, format="wav", tags={})
            st.audio(outp)
            with open(outp, "rb") as f:
                st.download_button("⬇️ Download Redacted Audio", f.read(), file_name="redacted_audio.wav", key="mr_audio_dl")
            st.success("🎧 Audio redaction done (beep replacements applied).")

# ---------- ROLE-BASED REDACTION ----------
with tabs[1]:
    st.subheader("👥 Role-Based Redaction (Text & PDF)")

    if "rb_logged_in" not in st.session_state:
        st.session_state.rb_logged_in = False
        st.session_state.rb_user = ""
        st.session_state.rb_role = ""

    if not st.session_state.rb_logged_in:
        st.info("Login using the format: name.role@sector (e.g., keerthi.admin@med)")
        login_input = st.text_input("Login (name.role@sector)", key="rb_login")
        password = st.text_input("Password (strong)", type="password", key="rb_pw")
        if st.button("Login (role-based)", key="rb_login_btn"):
            m = re.match(r"^([a-zA-Z0-9_]+)\.([a-zA-Z]+)@([a-zA-Z]+)$", login_input or "")
            if not m:
                st.error("Invalid format. Use name.role@sector (e.g., keerthi.admin@med)")
            elif not (password and len(password) >= 8 and re.search(r"[A-Z]", password) and re.search(r"[a-z]", password) and re.search(r"[0-9]", password) and re.search(r"[^\w\s]", password)):
                st.error("Weak password. Must be 8+ chars incl. upper, lower, digit, special.")
            else:
                username, role_str, sector = m.groups()
                st.session_state.rb_logged_in = True
                st.session_state.rb_user = username
                st.session_state.rb_role = role_str.lower()
                st.success(f"Logged in as {username} — role: {role_str}")
                st.rerun()

    else:
        st.sidebar.success(f"Logged in as {st.session_state.rb_user} ({st.session_state.rb_role})")
        if st.sidebar.button("Logout (role-based)", key="rb_logout"):
            st.session_state.rb_logged_in = False
            st.session_state.rb_user = ""
            st.session_state.rb_role = ""
            st.rerun()

        st.markdown("**Select PII types to redact (these choices are recorded in ledger)**")
        ENTITY_CHOICES = [
            ("PERSON","PERSON"),
            ("EMAIL_ADDRESS","EMAIL_ADDRESS"),
            ("PHONE_NUMBER","PHONE_NUMBER"),
            ("CREDIT_CARD","CREDIT_CARD"),
            ("DATE_TIME","DATE_TIME"),
            ("IP_ADDRESS","IP_ADDRESS")
        ]
        labels = [lab for lab,_ in ENTITY_CHOICES]
        defaults = ["PERSON","EMAIL_ADDRESS","PHONE_NUMBER"]
        opts = st.multiselect("Select types:", labels, default=[l for l in labels if l in defaults], key="rb_entity_select")
        selected_entities = [val for (lab,val) in ENTITY_CHOICES if lab in opts]

        rb_uploaded = st.file_uploader("Upload TXT or PDF (role-based)", type=["txt","pdf"], key="rb_file_upload")
        rb_encrypt = st.checkbox("Encrypt after redaction (AES) - role-based", key="rb_encrypt")
        if rb_uploaded and st.button("Redact File (Role)", key="rb_do_redact"):
            suffix = rb_uploaded.name.split(".")[-1].lower()
            tfile = tempfile.NamedTemporaryFile(delete=False, suffix=f".{suffix}")
            tfile.write(rb_uploaded.getbuffer()); tfile.close()
            cleaned = clean_metadata(tfile.name, suffix)
            role = st.session_state.rb_role
            user = st.session_state.rb_user
            sel_label = ", ".join(selected_entities) if selected_entities else "ALL"

            # TXT
            if suffix == "txt":
                with open(cleaned, "r", encoding="utf-8", errors="ignore") as f:
                    text = f.read()
                text = redact_text_presidio(text, selected_entity_types=selected_entities or None, role=role)
                out_bytes = text.encode("utf-8")
                if rb_encrypt:
                    key = get_random_bytes(16)
                    enc = encrypt_bytes(out_bytes, key)
                    st.code(f"AES key (hex): {key.hex()}")
                    st.download_button("⬇️ Download Encrypted TXT", enc, file_name="role_redacted_enc.txt", key="rb_dl_enc_txt")
                    file_hash = hashlib.sha256(enc).hexdigest()
                else:
                    st.download_button("⬇️ Download Redacted TXT", out_bytes, file_name="role_redacted.txt", key="rb_dl_txt")
                    file_hash = hashlib.sha256(out_bytes).hexdigest()
                append_block(user, role, f"Role Text Redaction [{sel_label}]", file_hash)
                st.success("✅ Role-based TXT redacted and recorded to ledger.")

            # PDF
            elif suffix == "pdf":
                doc = fitz.open(cleaned)
                for page in doc:
                    text = page.get_text()
                    results = analyzer.analyze(text=text, language="en")
                    for r in results:
                        ent_type = getattr(r, "entity_type", None)
                        if selected_entities and ent_type not in selected_entities:
                            continue
                        ent = text[r.start:r.end]
                        rects = page.search_for(ent)
                        for rect in rects:
                            if role != "admin":
                                page.add_redact_annot(rect, fill=(0,0,0))
                    page.apply_redactions()
                out = io.BytesIO(); doc.save(out)
                pdf_bytes = out.getvalue()
                if rb_encrypt:
                    key = get_random_bytes(16)
                    enc = encrypt_bytes(pdf_bytes, key)
                    st.code(f"AES key (hex): {key.hex()}")
                    st.download_button("⬇️ Download Encrypted PDF", enc, file_name="role_redacted_enc.pdf", key="rb_dl_enc_pdf")
                    file_hash = hashlib.sha256(enc).hexdigest()
                else:
                    st.download_button("⬇️ Download Redacted PDF", pdf_bytes, file_name="role_redacted.pdf", key="rb_dl_pdf")
                    file_hash = hashlib.sha256(pdf_bytes).hexdigest()
                append_block(user, role, f"Role PDF Redaction [{sel_label}]", file_hash)
                st.success("✅ Role-based PDF redacted and recorded to ledger.")

        st.markdown("---")
        st.markdown("### 📜 Ledger Verification (Role-Based: Text/PDF)")
        if st.button("Verify Ledger (Role)", key="verify_role"):
            res = verify_ledger()
            if res.startswith("✅"):
                st.success(res)
            else:
                st.error(res)

# ---------- DECRYPTION ----------
with tabs[2]:
    st.subheader("🔓 Decrypt Encrypted File (TXT / PDF)")
    dec_file = st.file_uploader("Upload Encrypted File (txt/pdf)", type=["txt","pdf"], key="dec_upload")
    dec_key = st.text_input("AES key (hex)", key="dec_key")
    if dec_file and dec_key and st.button("Decrypt Now", key="dec_go"):
        try:
            key_bytes = bytes.fromhex(dec_key.strip())
            enc_bytes = dec_file.getbuffer()
            dec = decrypt_bytes(enc_bytes, key_bytes)
            st.success("✅ Decrypted successfully.")
            if dec_file.name.endswith(".txt"):
                st.text_area("Decrypted Text", dec.decode("utf-8", errors="ignore"), height=300)
            st.download_button("⬇️ Download Decrypted File", dec, file_name="decrypted." + dec_file.name.split(".")[-1], key="dec_dl")
        except Exception as e:
            st.error(f"Decryption failed: {e}")
