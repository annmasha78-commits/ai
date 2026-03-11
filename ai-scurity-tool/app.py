import streamlit as st
import google.generativeai as genai
import requests
from bs4 import BeautifulSoup
import plotly.graph_objects as go
import re
from PIL import Image
import PyPDF2
import json
from fpdf import FPDF
import tempfile
import datetime
import tldextract
import time
import base64

# --- 1. AI Configuration (Gemini API Fallback) ---
genai.configure(api_key="AIzaSyC2xF7TA7wMhB3poUbl_ayKtT-opO5rOO4")

model = None
try:
    # Fetch all models that support content generation
    available_models = [m.name for m in genai.list_models() if 'generateContent' in m.supported_generation_methods]
    
    # Preferred models in order, ensuring they support formatting and image/text if possible
    preferred_models = [
        "models/gemini-pro",
        "models/gemini-1.5-pro-latest",
        "models/gemini-2.0-flash",
        "models/gemini-pro"
    ]
    
    # Find the nearest match
    for pref in preferred_models:
        if pref in available_models or pref.replace("models/", "") in available_models:
            model = genai.GenerativeModel(pref)
            break
            
    # Fallback to the first available model if preferences fail
    if not model and available_models:
        model = genai.GenerativeModel(available_models[0])
except Exception:
    # Absolute fallback
    model = genai.GenerativeModel('gemini-pro')

# --- 2. Web UI Design - Ultra Premium Dashboard ---
st.set_page_config(
    page_title="HexaShield Pro | Digital Forensics", 
    page_icon="🛡️", 
    layout="wide", 
    initial_sidebar_state="expanded"
)

# Custom CSS for Premium Look
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;800&display=swap');
    
    html, body, [class*="css"] {
        font-family: 'Inter', sans-serif;
    }
    
    /* Dark Premium Theme with Dark Blue/Purple Accents */
    .stApp { 
        background-color: #0b0f19; 
        color: #e2e8f0; 
    }
    
    /* Headers */
    h1, h2, h3 { 
        color: #60a5fa; 
        font-weight: 800;
        letter-spacing: -0.5px;
    }
    
    /* Cards and Containers */
    div[data-testid="metric-container"], .custom-card {
        background: rgba(17, 24, 39, 0.7);
        backdrop-filter: blur(10px);
        -webkit-backdrop-filter: blur(10px);
        border: 1px solid rgba(255, 255, 255, 0.1);
        padding: 20px; 
        border-radius: 16px; 
        box-shadow: 0 10px 30px rgba(0, 0, 0, 0.5);
        transition: transform 0.3s ease, box-shadow 0.3s ease;
    }
    
    div[data-testid="metric-container"]:hover {
        transform: translateY(-5px);
        border-color: rgba(96, 165, 250, 0.4);
        box-shadow: 0 15px 35px rgba(59, 130, 246, 0.2);
    }
    
    /* Sidebar */
    section[data-testid="stSidebar"] { 
        background-color: #111827; 
        border-right: 1px solid rgba(255,255,255,0.05); 
    }
    
    /* Buttons */
    .stButton>button {
        background: linear-gradient(135deg, #3b82f6 0%, #2563eb 100%);
        color: white; 
        border: none; 
        border-radius: 8px; 
        padding: 10px 24px; 
        font-weight: 600; 
        letter-spacing: 0.5px;
        transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
        box-shadow: 0 4px 12px rgba(37, 99, 235, 0.3);
    }
    
    .stButton>button:hover { 
        transform: translateY(-2px);
        box-shadow: 0 8px 20px rgba(37, 99, 235, 0.5);
        background: linear-gradient(135deg, #60a5fa 0%, #3b82f6 100%);
    }
    
    /* Inputs */
    .stTextArea textarea, .stTextInput input {
        background-color: #1f2937 !important;
        color: #f3f4f6 !important;
        border: 1px solid #374151 !important;
        border-radius: 8px !important;
        padding: 12px !important;
    }
    .stTextArea textarea:focus, .stTextInput input:focus {
        border-color: #3b82f6 !important;
        box-shadow: 0 0 0 2px rgba(59, 130, 246, 0.2) !important;
    }
    
    /* Status spinners and progress */
    .stProgress .st-bo { background-color: #3b82f6; }
    
    /* Divider */
    hr {
        border-color: rgba(255,255,255,0.1);
        margin: 2rem 0;
    }
</style>
""", unsafe_allow_html=True)

# Hero Section
st.markdown("""
<div style='text-align: center; padding: 40px 20px; border-radius: 20px; background: linear-gradient(145deg, #111827, #0b0f19); border: 1px solid rgba(255,255,255,0.05); box-shadow: 0 20px 40px rgba(0,0,0,0.4); margin-bottom: 40px; position: relative; overflow: hidden;'>
    <div style="position: absolute; top: -50%; left: -50%; width: 200%; height: 200%; background: radial-gradient(circle, rgba(59,130,246,0.05) 0%, rgba(0,0,0,0) 70%); pointer-events: none;"></div>
    <div style='display: flex; justify-content: center; align-items: center; gap: 15px; margin-bottom: 10px;'>
        <img src="https://img.icons8.com/nolan/96/shield.png" width="64"/>
        <h1 style='margin:0; font-size: 52px; color: #ffffff; font-weight: 800; text-shadow: 0 0 20px rgba(59, 130, 246, 0.5);'>HexaShield <span style="color: #3b82f6;">Pro</span></h1>
    </div>
    <p style='color: #9ca3af; font-size: 18px; max-width: 600px; margin: 0 auto; line-height: 1.6;'>Enterprise-Grade Zero-Day Threat, Phishing & Cognitive Security Forensics Engine</p>
</div>
""", unsafe_allow_html=True)

# --- 3. Core Logic & Helpers ---
def check_domain_spoofing(url):
    is_suspicious = False
    warnings = []
    extracted_info = {}
    if not url: return {"is_suspicious": is_suspicious, "warnings": warnings, "extracted_info": extracted_info}
    try:
        extracted = tldextract.extract(url)
        domain, subdomain, suffix = extracted.domain, extracted.subdomain, extracted.suffix.lower()
        extracted_info = {"domain": domain, "subdomain": subdomain, "suffix": suffix}
        if len(domain) > 25:
            warnings.append(f"Domain '{domain}' is unusually long (>25 chars), indicative of spoofing.")
            is_suspicious = True
        if domain.count('-') > 2:
            warnings.append(f"Multiple hyphens detected in '{domain}', common in typosquatting.")
            is_suspicious = True
        suspicious_tlds = ['xyz', 'biz', 'info', 'top', 'tk', 'ml', 'ga', 'cf', 'gq', 'online', 'vip', 'click', 'site']
        if suffix in suspicious_tlds:
            warnings.append(f"Highly abused Top Level Domain (.{suffix}) detected.")
            is_suspicious = True
        brands = ["paypal", "login", "support", "apple", "google", "microsoft", "amazon", "netflix", "bank", "account", "verify", "secure"]
        for brand in brands:
            if brand in subdomain.lower() and brand not in domain.lower():
                warnings.append(f"Deceptive Subdomain: '{brand}' found in subdomain '{subdomain}' masking the true domain '{domain}'.")
                is_suspicious = True
        if re.search(r'[0-9]{2,}', domain) and suffix in ['com', 'net', 'org']:
             warnings.append("Numeric substitution in domain name detected (possible homograph attack).")
    except Exception as e:
        warnings.append(f"Could not parse domain structure correctly: {e}")
        is_suspicious = True
    return {"is_suspicious": is_suspicious, "warnings": list(set(warnings)), "extracted_info": extracted_info}

def create_gauge_chart(score):
    if score <= 30: 
        bar_color, text_color, risk_text = "#10b981", "#34d399", "SECURE"
    elif score <= 70: 
        bar_color, text_color, risk_text = "#f59e0b", "#fbbf24", "SUSPICIOUS"
    else: 
        bar_color, text_color, risk_text = "#ef4444", "#f87171", "CRITICAL THREAT"

    fig = go.Figure(go.Indicator(
        mode = "gauge+number", 
        value = score, 
        domain = {'x': [0, 1], 'y': [0, 1]},
        title = {'text': f"<br><span style='font-size:1em;color:{text_color}; font-weight:bold;'>{risk_text}</span>", 'font': {'size': 20, 'family': 'Inter'}},
        number = {'font': {'color': "#ffffff", 'size': 50, 'family': 'Inter', 'weight': 'bold'}, 'suffix': "/100"},
        gauge = {
            'axis': {'range': [None, 100], 'tickwidth': 2, 'tickcolor': "#4b5563"},
            'bar': {'color': bar_color, 'thickness': 0.75}, 
            'bgcolor': "rgba(31, 41, 55, 0.5)", 
            'borderwidth': 0, 
            'bordercolor': "transparent",
            'steps': [
                {'range': [0, 30], 'color': 'rgba(16, 185, 129, 0.15)'}, 
                {'range': [31, 70], 'color': 'rgba(245, 158, 11, 0.15)'}, 
                {'range': [71, 100], 'color': 'rgba(239, 68, 68, 0.15)'}
            ],
            'threshold': {
                'line': {'color': "white", 'width': 4},
                'thickness': 0.8,
                'value': score
            }
        }
    ))
    fig.update_layout(
        height=320, 
        margin=dict(l=20, r=20, t=50, b=20), 
        paper_bgcolor="rgba(0,0,0,0)", 
        plot_bgcolor="rgba(0,0,0,0)",
        font={'color': "white", 'family': 'Inter'}
    )
    return fig

def fetch_text_from_url(url):
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
    }
    try:
        response = requests.get(url, headers=headers, timeout=12, allow_redirects=True)
        response.raise_for_status()
        soup = BeautifulSoup(response.content, 'html.parser')
        for script in soup(["script", "style", "noscript", "meta", "link"]): script.extract()
        text = re.sub(r'\s+', ' ', soup.get_text(separator=' ', strip=True))
        return {"success": True, "text": text[:20000]} # Increased chunk size for better analysis
    except requests.exceptions.RequestException as e:
        return {"success": False, "error": f"Network Error: {e}"}

def extract_text_from_pdf(pdf_file):
    try:
        pdf_reader = PyPDF2.PdfReader(pdf_file)
        text = "\n".join([page.extract_text() for page in pdf_reader.pages if page.extract_text()])
        if not text.strip(): return {"success": False, "error": "Document appears to be an image-only PDF. OCR is required."}
        return {"success": True, "text": text[:20000]}
    except Exception as e:
        return {"success": False, "error": f"PDF Parsing Error: {e}"}

def clean_for_pdf(text):
    text = str(text)
    text = text.replace('‘', "'").replace('’', "'").replace('"', '"').replace('"', '"').replace('–', '-').replace('—', '-')
    text = re.sub(r'\*\*(.*?)\*\*', r'\1', text) # Remove markdown bold
    text = re.sub(r'\*(.*?)\*', r'\1', text) # Remove markdown italic
    text = re.sub(r'#(.*)', r'\1', text) # Remove markdown headers
    return re.sub(r'[^\x00-\x7F]+', ' ', text)

def create_json_report(score, analysis_text, content_type, spoofing_data=None):
    return json.dumps({
        "metadata": {
            "platform": "HexaShield Pro AI", 
            "scan_timestamp": datetime.datetime.now().isoformat(), 
            "target_vector": content_type
        },
        "telemetry": {
            "threat_quotient": score, 
            "risk_level": "SECURE" if score <= 30 else "SUSPICIOUS" if score <= 70 else "CRITICAL"
        },
        "indicators_of_compromise": spoofing_data or [],
        "ai_forensic_analysis": analysis_text
    }, indent=4)

class PDFReport(FPDF):
    def header(self):
        # Header banner
        self.set_fill_color(11, 15, 25) # Dark blue/black
        self.rect(0, 0, 210, 40, 'F')
        
        # Title
        self.set_font("Arial", 'B', 24)
        self.set_text_color(255, 255, 255)
        self.set_xy(15, 12)
        self.cell(0, 10, "HEXASHIELD PRO", ln=True)
        
        # Subtitle
        self.set_font("Arial", '', 12)
        self.set_text_color(156, 163, 175) # Gray-400
        self.set_xy(15, 22)
        self.cell(0, 10, "Cyber Intelligence & Incident Response Report", ln=True)
        
        # Decorative line
        self.set_draw_color(59, 130, 246) # Blue-500
        self.set_line_width(1)
        self.line(15, 38, 195, 38)
        self.ln(20)

    def footer(self):
        self.set_y(-20)
        self.set_font("Arial", 'I', 8)
        self.set_text_color(156, 163, 175)
        self.set_line_width(0.2)
        self.set_draw_color(200, 200, 200)
        self.line(15, self.get_y(), 195, self.get_y())
        self.cell(0, 10, f"Page {self.page_no()}", 0, 0, 'C')
        self.set_x(15)
        self.cell(0, 10, "CONFIDENTIAL & PROPRIETARY", 0, 0, 'L')
        self.set_x(-60)
        self.cell(45, 10, datetime.datetime.now().strftime('%Y-%m-%d %H:%M UTC'), 0, 0, 'R')

    def chapter_title(self, title, bg_color=(243, 244, 246)):
        self.ln(5)
        self.set_font("Arial", 'B', 14)
        self.set_fill_color(*bg_color)
        self.set_text_color(17, 24, 39)
        self.cell(0, 10, f"  {title}", 0, 1, 'L', fill=True)
        self.ln(4)

    def chapter_body(self, text):
        self.set_font("Arial", '', 11)
        self.set_text_color(55, 65, 81)
        self.multi_cell(0, 6, text)
        self.ln(5)

def create_pdf_report(score, analysis_text, content_type, target_value, uploaded_image=None, domain_warnings=None):
    pdf = PDFReport()
    pdf.add_page()
    
    # --- METADATA SECTION ---
    pdf.set_font("Arial", 'B', 12)
    pdf.set_text_color(17, 24, 39)
    pdf.cell(40, 8, "Scan ID:", 0, 0)
    pdf.set_font("Arial", '', 12)
    pdf.cell(0, 8, f"HX-{int(time.time())}", 0, 1)
    
    pdf.set_font("Arial", 'B', 12)
    pdf.cell(40, 8, "Target Type:", 0, 0)
    pdf.set_font("Arial", '', 12)
    pdf.cell(0, 8, str(content_type).title(), 0, 1)
    
    pdf.set_font("Arial", 'B', 12)
    pdf.cell(40, 8, "Target ID:", 0, 0)
    pdf.set_font("Arial", '', 11)
    # Truncate very long texts for the header
    safe_target = clean_for_pdf(str(target_value).replace(chr(10), ' '))[:90] + "..." if len(str(target_value)) > 90 else clean_for_pdf(str(target_value).replace(chr(10), ' '))
    pdf.cell(0, 8, safe_target, 0, 1)
    
    pdf.ln(5)
    
    # --- THREAT SCORE CARD ---
    if score <= 30: 
        bg = (209, 250, 229) # Green bg
        text_color = (6, 95, 70) # Green text
        rs = "SECURE"
    elif score <= 70: 
        bg = (254, 243, 199) # Yellow bg
        text_color = (146, 64, 14) # Yellow text
        rs = "SUSPICIOUS"
    else: 
        bg = (254, 226, 226) # Red bg
        text_color = (153, 27, 27) # Red text
        rs = "CRITICAL RISK"
        
    pdf.set_fill_color(*bg)
    pdf.rect(15, pdf.get_y(), 180, 20, 'F')
    pdf.set_xy(15, pdf.get_y() + 5)
    pdf.set_font("Arial", 'B', 16)
    pdf.set_text_color(*text_color)
    pdf.cell(0, 10, f"OVERALL THREAT VERDICT: {score}/100 - {rs}", 0, 1, 'C')
    pdf.ln(10)

    # --- TECHNICAL ALERTS ---
    if domain_warnings:
        pdf.chapter_title("TECHNICAL INDICATORS (IOCs)", (254, 226, 226))
        pdf.set_font("Arial", '', 11)
        pdf.set_text_color(153, 27, 27)
        for w in domain_warnings: 
            pdf.cell(5, 6, "-", 0, 0)
            pdf.multi_cell(0, 6, clean_for_pdf(w))
        pdf.ln(5)

    # --- IMAGE EVIDENCE ---
    if uploaded_image:
        pdf.chapter_title("FORENSIC EVIDENCE")
        try:
            with tempfile.NamedTemporaryFile(delete=False, suffix=".png") as tmp_img:
                img_rgb = uploaded_image.convert('RGB')
                # Resize keeping aspect ratio
                img_rgb.thumbnail((160, 160))
                img_rgb.save(tmp_img.name, format="PNG")
                
                # Center image
                x_pos = (210 - img_rgb.width * (160/img_rgb.width if img_rgb.width > 160 else 1)) / 2
                if x_pos < 15: x_pos = 15
                
                pdf.image(tmp_img.name, x=25, w=160)
                pdf.ln(5)
        except Exception as e: 
            pdf.set_text_color(255,0,0)
            pdf.cell(0, 10, f"[Failed to process image evidence: {e}]", 0, 1)
            
    # --- AI ANALYSIS ---
    pdf.chapter_title("AI FORENSIC REASONING & REMEDIATION", (224, 242, 254))
    
    # Format the analysis text to look better in PDF
    analysis_lines = analysis_text.split(chr(10))
    pdf.set_font("Arial", '', 11)
    pdf.set_text_color(55, 65, 81)
    
    for line in analysis_lines:
        line = line.strip()
        if not line:
            pdf.ln(3)
            continue
            
        # Format Headers
        if line.startswith('###'):
            pdf.ln(4)
            pdf.set_font("Arial", 'B', 12)
            pdf.set_text_color(17, 24, 39)
            pdf.cell(0, 8, clean_for_pdf(line.replace('#', '').strip()), 0, 1)
            pdf.set_font("Arial", '', 11)
            pdf.set_text_color(55, 65, 81)
        elif line.startswith('**') or line.startswith('- **'):
            pdf.set_font("Arial", 'B', 11)
            pdf.multi_cell(0, 6, clean_for_pdf(line))
            pdf.set_font("Arial", '', 11)
        else:
            pdf.multi_cell(0, 6, clean_for_pdf(line))

    return pdf.output(dest="S").encode('latin-1')

# --- 4. Sidebar Navigation ---
with st.sidebar:
    st.markdown("""
    <div style='text-align: center; margin-bottom: 20px;'>
        <img src="https://img.icons8.com/nolan/128/shield.png" width="80"/>
        <h2 style='margin-top: 5px; color: white;'>Navigation</h2>
    </div>
    """, unsafe_allow_html=True)
    
    st.markdown("<p style='color: #9ca3af; font-size: 14px; margin-bottom: 5px; text-transform: uppercase; letter-spacing: 1px;'>Select Module</p>", unsafe_allow_html=True)
    
    app_mode = st.radio(
        "", 
        [
            "📝 Text & Script Analysis", 
            "🔗 Domain Surgery & Web Scan", 
            "🖼️ OCR & Vision (UI/PDF Forensics)"
        ], 
        label_visibility="collapsed"
    )
    
    st.markdown("<hr style='border-color: #374151;'>", unsafe_allow_html=True)
    
    st.markdown("""
    <div style='background: rgba(31, 41, 55, 0.5); padding: 15px; border-radius: 10px; border: 1px solid #374151;'>
        <h4 style='margin-top:0; color:#60a5fa; font-size: 14px;'>System Status</h4>
        <div style='display: flex; align-items: center; gap: 10px; margin-top: 10px;'>
            <div style='width: 10px; height: 10px; border-radius: 50%; background-color: #10b981; box-shadow: 0 0 10px #10b981;'></div>
            <span style='color: #d1d5db; font-size: 13px;'>Gemini 1.5 Pro Engine: <b>Online</b></span>
        </div>
        <div style='display: flex; align-items: center; gap: 10px; margin-top: 8px;'>
            <div style='width: 10px; height: 10px; border-radius: 50%; background-color: #10b981; box-shadow: 0 0 10px #10b981;'></div>
            <span style='color: #d1d5db; font-size: 13px;'>Spoof Heuristics: <b>Active</b></span>
        </div>
    </div>
    """, unsafe_allow_html=True)
    
    st.markdown("<br><p style='text-align: center; color: #6b7280; font-size: 12px;'>HexaShield Enterprise v2.5</p>", unsafe_allow_html=True)

# --- 5. Main Interface ---
run_analysis = False
target_text = ""
target_image = None
context_info = ""
target_identifier = ""
domain_spoof_alerts = []

# Module Definitions
if app_mode == "📝 Text & Script Analysis":
    st.markdown("### 📝 Cognitive Text & Script Threat Analysis")
    st.markdown("<p style='color:#9ca3af; margin-bottom: 20px;'>Deploy deep NLP models to analyze suspicious emails, SMS messages, script chunks, or text snippets for psychological manipulation, phishing logic, or embedded payloads.</p>", unsafe_allow_html=True)
    
    user_text = st.text_area("Input Suspicious Content for Deep Inspection:", height=250, placeholder="Paste email content, text messages, or code snippets here...")
    
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        if st.button("🚀 INITIATE THREAT ANALYSIS", use_container_width=True):
            if user_text.strip():
                target_text = user_text
                target_identifier = "User Text Input"
                context_info = "text snippet or email"
                run_analysis = True
            else: 
                st.warning("⚠️ Payload empty. Please provide content to analyze.")

elif app_mode == "🔗 Domain Surgery & Web Scan":
    st.markdown("### 🔗 Domain Surgery & Deep Web Identity Scan")
    st.markdown("<p style='color:#9ca3af; margin-bottom: 20px;'>Execute real-time heuristic checks against target URLs to detect homograph attacks, typosquatting, and parse hidden malicious payloads from live sites.</p>", unsafe_allow_html=True)
    
    col1, col2 = st.columns([3, 1])
    with col1:
        user_url = st.text_input("Enter Target URI:", placeholder="https://secure-login.apple-verification-update.com")
    with col2:
        st.write("")
        st.write("")
        scan_btn = st.button("🌐 SCAN INTEGRITY", use_container_width=True)

    if scan_btn:
        if user_url.strip():
            if not user_url.startswith("http"): user_url = "https://" + user_url
            target_identifier = user_url    
            
            with st.status("📡 Establishing Secure Connection & Profiling Target...", expanded=True) as status:
                st.write("⏳ Extracting Domain Topology (Spoof Check)...")
                time.sleep(0.5) # Simulate processing for UI feel
                spoof_check = check_domain_spoofing(user_url)
                
                ext = spoof_check.get("extracted_info")
                if isinstance(ext, dict) and ext:
                    d_val = ext.get('domain', '')
                    s_val = ext.get('suffix', '')
                    sub_val = ext.get('subdomain', '')
                    st.markdown(f"**🔍 Domain Surgery (TLDExtract):** Parsing URL to detect real domain vs subdomains.<br>&nbsp;&nbsp;&nbsp;&nbsp;↳ **True Domain:** `{d_val}.{s_val}`<br>&nbsp;&nbsp;&nbsp;&nbsp;↳ **Subdomain:** `{sub_val if sub_val else 'None'}`", unsafe_allow_html=True)

                if spoof_check["is_suspicious"]:
                    domain_spoof_alerts = spoof_check["warnings"]
                    st.write("❌ Critical anomalies found in domain structure.")
                else: 
                    st.write("✅ Domain structure passes preliminary heuristics.")
                    
                st.write("⏳ Dispatching Stealth Request (Scraping Content)...")
                fetch_res = fetch_text_from_url(user_url)
                
                if fetch_res["success"]:
                    target_text = fetch_res["text"]
                    context_info = f"website URL ({user_url})"
                    st.write("✅ Payload acquired successfully. Initiating transfer to AI module.")
                    status.update(label="Target Acquired! Handing off to AI Engine...", state="complete", expanded=False)
                    run_analysis = True
                else:
                    st.error(f"Execution Failed: Unable to breach target server.\\n{fetch_res['error']}")
                    status.update(label="Reconnaissance Failed", state="error")
        else: 
            st.warning("⚠️ Invalid URI. Please provide a structurally valid URL.")

elif app_mode == "🖼️ OCR & Vision (UI/PDF Forensics)":
    st.markdown("### 🖼️ OCR & Vision (UI Dark Pattern Forensics)")
    st.markdown("<p style='color:#9ca3af; margin-bottom: 20px;'>Upload visual evidence (screenshots of interfaces) or documents (PDFs) to detect forced continuity, fake urgency, hidden malicious macros, or deceptive design architectures.</p>", unsafe_allow_html=True)
    
    uploaded_file = st.file_uploader("Upload Evidence Container (PNG/JPG/PDF):", type=['png', 'jpg', 'jpeg', 'pdf'])
    
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        if st.button("🔎 EXECUTE FORENSIC EXTRACTION", use_container_width=True):
            if uploaded_file:
                target_identifier = uploaded_file.name
                if uploaded_file.name.lower().endswith('.pdf'):
                    with st.spinner("Decrypting and extracting metadata/text from PDF..."):
                        pdf_res = extract_text_from_pdf(uploaded_file)
                        if pdf_res["success"]:
                            target_text = pdf_res["text"]
                            context_info = "PDF Document"
                            run_analysis = True
                        else: 
                            st.error(f"Extraction Failure: {pdf_res['error']}")
                else:
                    try:
                        target_image = Image.open(uploaded_file)
                        st.success("🔍 **OCR & Vision Engine Active:** Scanning pixels for Malicious UI elements...")
                        target_text = "Thoroughly scan the pixels using OCR and Vision capabilities. Analyze the provided UI layout, texts, and design elements within this image/screenshot to determine its true intent, explicitly checking for Malicious UI elements, forced UX dark patterns, fake urgency, hidden costs, and deceptive buttons."
                        context_info = "Image/Screenshot UI"
                        run_analysis = True
                        st.markdown("<br><p style='text-align:center; color:#9ca3af;'>Uploaded Image Evidence:</p>", unsafe_allow_html=True)
                        st.image(target_image, caption="Exhibit A", use_container_width=True)
                    except Exception as e: 
                        st.error(f"Corrupted Image File: {e}")
            else: 
                st.warning("⚠️ No evidence uploaded. Please mount a file first.")

# --- 6. AI Analysis Pipeline ---
if run_analysis:
    if not model:
        st.error("❌ CRITICAL: Gemini AI reasoning cluster is offline.")
        st.stop()
        
    st.markdown("<hr style='border-color: #374151; margin-top: 40px;'>", unsafe_allow_html=True)
    st.markdown("<h2 style='text-align: center;'>🧠 Forensic AI Evaluation</h2>", unsafe_allow_html=True)
    
    with st.spinner("Processing vectors through HexaShield Neural Network..."):
        prompt = f'''You are an elite Cyber Security Analyst, Fraud Investigator, and UX Dark Pattern Expert.
Your ONLY goal is to analyze the provided {context_info} and output an extremely structured, highly professional, corporate-grade security report.

CRITICAL FORMATTING INSTRUCTION:
You MUST output EXACTLY `[SCORE: X]` on the very FIRST line of your response (X = 0 to 100).
0 = Completely Safe, 100 = Guaranteed Malicious Scam/Phishing. Do not write anything before the score.

### Report Output Structure Required (Use exact markdown headers):

### 📊 Executive Threat Summary
(1-2 clear sentences summarizing the overall risk level and primary concern for a C-level executive).

### 🚩 Identified Attack Vectors & Red Flags
(Use bullet points. Specifically call out Phishing tactics, Fake Authority, Brand Impersonation, or urgency triggers).

### 🕷️ UX/Psychological Mechanics Breakdown
(Deeply analyze what cognitive tricks or UI mechanics the payload uses to manipulate the victim).

### 🛡️ Recommended Remediation & Incident Response
(High-priority, actionable steps: what exactly should the user/organization do right now to mitigate risk?).

---
Target Content:
"""
{target_text}
"""
'''
        try:
            start_time = time.time()
            # Send to Gemini
            if target_image:
                response = model.generate_content([prompt, target_image])
            else:
                response = model.generate_content(prompt)
                
            process_time = round(time.time() - start_time, 2)
            result_text = response.text
            
            # Extract Score safely
            score_match = re.search(r'\[SCORE:\s*(\d+)\]', result_text, re.IGNORECASE)
            threat_score = int(score_match.group(1)) if score_match else 50
            
            # Clean text for display
            display_text = re.sub(r'\[SCORE:\s*\d+\]\n?', '', result_text, flags=re.IGNORECASE).strip()
            
            if not score_match: 
                st.warning("⚠️ Confidence rating parsed with errors, defaulting to baseline 50.")

            # Display Results Container
            st.markdown(f"""
            <div style='background: rgba(16, 185, 129, 0.1); border: 1px solid #10b981; padding: 10px; border-radius: 8px; margin-bottom: 20px; text-align: center;'>
                <span style='color: #10b981; font-weight: 600;'>✅ Scan completed successfully in {process_time} seconds</span>
            </div>
            """, unsafe_allow_html=True)
            
            # IOCs Banner
            if domain_spoof_alerts:
                st.error("**🚨 CRITICAL INDICATORS OF COMPROMISE DETECTED:** Domain heuristics indicate high spoofing probability.")
                for alert in domain_spoof_alerts: 
                    st.markdown(f"<span style='color: #ef4444;'>► {alert}</span>", unsafe_allow_html=True)
            
            # Results Layout
            res_col1, res_col2 = st.columns([1, 2], gap="large")
            
            with res_col1:
                # Gauge Chart
                st.plotly_chart(create_gauge_chart(threat_score), use_container_width=True)
                
                # Meta info box
                st.markdown("""
                <div style='background: rgba(31, 41, 55, 0.5); padding: 20px; border-radius: 12px; border: 1px solid #374151; margin-bottom: 20px;'>
                    <h3 style='margin-top:0; font-size: 18px;'>📡 Telemetry Meta</h3>
                    <p style='color: #9ca3af; margin: 5px 0;'>Payload Size: <strong style='color: #e2e8f0;'>{} bytes</strong></p>
                    <p style='color: #9ca3af; margin: 5px 0;'>Target Vector: <strong style='color: #e2e8f0;'>{}</strong></p>
                </div>
                """.format(len(str(target_text)), str(context_info).title()), unsafe_allow_html=True)
                
                # Reports Section
                st.markdown("<h3 style='font-size: 18px;'>🖨️ Export Intelligence</h3>", unsafe_allow_html=True)
                
                json_rpt = create_json_report(threat_score, display_text, context_info, domain_spoof_alerts)
                st.download_button(
                    label="🔽 Download JSON (Syslog)", 
                    data=json_rpt, 
                    file_name=f"hx_scan_{int(time.time())}.json", 
                    mime="application/json", 
                    use_container_width=True
                )
                
                try:
                    pdf_rpt = create_pdf_report(threat_score, display_text, context_info, target_identifier, target_image, domain_spoof_alerts)
                    st.download_button(
                        label="📑 Download PDF (C-Level)", 
                        data=pdf_rpt, 
                        file_name=f"hx_exec_report_{int(time.time())}.pdf", 
                        mime="application/pdf", 
                        use_container_width=True
                    )
                except Exception as e: 
                    st.error(f"PDF Compiler Error: {e}")

            with res_col2:
                # Detailed Analysis Box
                st.markdown(f"""
                <div style='background: rgba(17, 24, 39, 0.8); padding: 30px; border-radius: 12px; border: 1px solid #374151; box-shadow: inset 0 2px 10px rgba(0,0,0,0.5); height: 100%; border-top: 4px solid {"#10b981" if threat_score <=30 else "#f59e0b" if threat_score <=70 else "#ef4444"};'>
                    {display_text.replace('###', '####')}  
                </div>
                """, unsafe_allow_html=True)
                
        except Exception as ai_err: 
            st.error(f"❌ Core Engine Failure: {ai_err}")

# Footer
st.markdown("<br><hr style='border-color: #1f2937;'>", unsafe_allow_html=True)
st.markdown("""
<div style='text-align: center; color: #4b5563; font-size: 13px; font-family: monospace;'>
    HEXASHIELD PRO ADVANCED THREAT INTELLIGENCE CENTER<br>
    BUILD v2.5.9 | SECURE FRAMEWORK ENABLED
</div>
""", unsafe_allow_html=True)
