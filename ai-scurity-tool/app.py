import streamlit as st
import google.generativeai as genai
import requests
from bs4 import BeautifulSoup
import plotly.graph_objects as go
import re
from PIL import Image
import PyPDF2
import io
import json
from fpdf import FPDF
import tempfile
import datetime
import tldextract

# 1. AI Configuration (Gemini API use karenge)
genai.configure(api_key="AIzaSyC2xF7TA7wMhB3poUbl_ayKtT-opO5rOO4") # User provided API key
model = genai.GenerativeModel('gemini-1.5-flash')

# 2. Web UI Design - Professional Dashboard
st.set_page_config(page_title="Cyber Security Dashboard", page_icon="🛡️", layout="wide")

st.markdown("""
<div style='text-align: center; padding: 10px; border-radius: 10px; background-color: #0b1a2a; color: #4dc3ff; border: 1px solid #1a365d;'>
    <h1>🛡️ Advanced Zero-Day Threat Intelligence Center</h1>
    <p style='font-size: 18px;'>AI-Powered Phishing, Domain Spoofing, Dark Pattern & UX Security Analyst</p>
</div>
<br>
""", unsafe_allow_html=True)

# Domain Spoofing Checker (Technical Logic)
def check_domain_spoofing(url):
    is_suspicious = False
    warnings = []
    
    if not url: 
        return {"is_suspicious": is_suspicious, "warnings": warnings}
    
    # Extract domain
    extracted = tldextract.extract(url)
    domain = extracted.domain
    subdomain = extracted.subdomain
    
    # Check 1: Homograph/Look-alike characters
    # If the domain is very complex or contains weird hyphens
    if len(domain) > 25:
        warnings.append("Domain is unusually long, common in hiding spoofed names.")
        is_suspicious = True
    if domain.count('-') > 2:
        warnings.append("Multiple hyphens detected, often used in typosquatting.")
        is_suspicious = True
        
    # Check 2: Top Level Domain (TLD) trust
    suspicious_tlds = ['xyz', 'biz', 'info', 'top', 'tk', 'ml', 'ga', 'cf', 'gq', 'online', 'vip']
    if extracted.suffix.lower() in suspicious_tlds:
        warnings.append(f"Suspicious Top Level Domain (.{extracted.suffix}) detected.")
        is_suspicious = True
        
    # Check 3: Subdomain hiding
    if "paypal" in subdomain or "login" in subdomain or "support" in subdomain or "apple" in subdomain or "google" in subdomain:
        warnings.append("Highly suspicious subdomain used to spoof a legitimate service.")
        is_suspicious = True
        
    return {"is_suspicious": is_suspicious, "warnings": warnings}

# Helper function to create Graph
def create_gauge_chart(score):
    if score <= 30:
        color = "#00ff00"
        text = "Safe"
    elif score <= 70:
        color = "#ffaa00" 
        text = "Suspicious"
    else:
        color = "#ff0000"
        text = "Critical Risk"

    fig = go.Figure(go.Indicator(
        mode = "gauge+number",
        value = score,
        domain = {'x': [0, 1], 'y': [0, 1]},
        title = {'text': f"Risk-O-Meter: {text}", 'font': {'size': 24, 'color': color}},
        gauge = {
            'axis': {'range': [None, 100], 'tickwidth': 1, 'tickcolor': "white"},
            'bar': {'color': color},
            'bgcolor': "rgba(0,0,0,0)",
            'borderwidth': 2,
            'bordercolor': "gray",
            'steps': [
                {'range': [0, 30], 'color': 'rgba(0, 255, 0, 0.15)'},
                {'range': [31, 70], 'color': 'rgba(255, 170, 0, 0.15)'},
                {'range': [71, 100], 'color': 'rgba(255, 0, 0, 0.15)'}],
        }
    ))
    fig.update_layout(height=350, margin=dict(l=10, r=10, t=50, b=10), paper_bgcolor="rgba(0,0,0,0)", font={'color': "white"})
    return fig

# Helper function to extract text from URL
def fetch_text_from_url(url):
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        soup = BeautifulSoup(response.content, 'html.parser')
        for script in soup(["script", "style"]):
            script.extract()
        text = soup.get_text(separator=' ', strip=True)
        return text[:10000] 
    except Exception as e:
        return f"Error fetching URL: {e}"

# Helper function to extract text from PDF
def extract_text_from_pdf(pdf_file):
    try:
        pdf_reader = PyPDF2.PdfReader(pdf_file)
        text = ""
        for page in pdf_reader.pages:
            text += page.extract_text() + "\n"
        return text[:10000]
    except Exception as e:
        return f"Error reading PDF: {e}"

# Report Generators
def create_json_report(score, analysis_text, content_type, spoofing_data=None):
    report_data = {
        "report_metadata": {
            "timestamp": datetime.datetime.now().isoformat(),
            "input_type": content_type,
            "security_clearance": "Automated Risk Assessment"
        },
        "quantitative_metrics": {
            "threat_score": score,
            "risk_level": "Safe" if score <= 30 else "Suspicious" if score <= 70 else "Dangerous"
        },
        "technical_spoofing_checks": spoofing_data if spoofing_data else "N/A",
        "zero_day_ai_analysis": analysis_text
    }
    return json.dumps(report_data, indent=4)

def create_pdf_report(score, analysis_text, uploaded_image=None, domain_warnings=None):
    pdf = FPDF()
    pdf.add_page()
    
    # Headers
    pdf.set_font("Arial", 'B', 18)
    pdf.set_text_color(0, 51, 102)
    pdf.cell(200, 10, txt="COMPREHENSIVE ZERO-DAY THREAT REPORT", ln=True, align='C')
    pdf.ln(5)
    
    # Meta
    pdf.set_font("Arial", 'I', 10)
    pdf.set_text_color(100, 100, 100)
    pdf.cell(200, 10, txt=f"Generated on: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')} (Automated Security Scan)", ln=True, align='C')
    pdf.ln(5)
    
    # Risk Box
    risk_level = "SAFE" if score <= 30 else "SUSPICIOUS (Manual Review Suggested)" if score <= 70 else "CRITICAL RISK (Malicious)"
    pdf.set_font("Arial", 'B', 14)
    if score > 70:
        pdf.set_text_color(200, 0, 0)
    elif score > 30:
        pdf.set_text_color(200, 150, 0)
    else:
        pdf.set_text_color(0, 150, 0)
    pdf.cell(200, 10, txt=f"Overall Threat Score: {score}/100 - {risk_level}", ln=True)
    pdf.ln(5)
    
    # Domain Spoofing Data
    if domain_warnings:
        pdf.set_font("Arial", 'B', 12)
        pdf.set_text_color(200, 0, 0)
        pdf.cell(200, 10, txt="⚠️ Technical Domain Spoofing Alerts:", ln=True)
        pdf.set_text_color(0, 0, 0)
        pdf.set_font("Arial", '', 10)
        for warn in domain_warnings:
            pdf.cell(200, 8, txt=f"- {warn}", ln=True)
        pdf.ln(5)

    # Image
    if uploaded_image:
        pdf.set_font("Arial", 'B', 12)
        pdf.set_text_color(0, 51, 102)
        pdf.cell(200, 10, txt="Visual Evidence Analysed:", ln=True)
        try:
            with tempfile.NamedTemporaryFile(delete=False, suffix=".jpg") as tmp_img:
                img_rgb = uploaded_image.convert('RGB')
                img_rgb.save(tmp_img.name)
                pdf.image(tmp_img.name, x=10, w=150)
                pdf.ln(10)
        except Exception:
            pass 
            
    # AI Report
    pdf.set_font("Arial", 'B', 12)
    pdf.set_text_color(0, 51, 102)
    pdf.cell(200, 10, txt="Zero-Day AI Analysis & Dark Pattern UI Highlights:", ln=True)
    
    pdf.set_font("Arial", '', 11)
    pdf.set_text_color(0, 0, 0)
    clean_text = analysis_text.encode('latin-1', 'replace').decode('latin-1')
    pdf.multi_cell(0, 7, txt=clean_text)
    
    return pdf.output(dest="S").encode('latin-1')

# 3. User Input (Tabs)
tab1, tab2, tab3 = st.tabs(["📝 Text/Script Analysis", "🔗 Deep URL & Spoof Scan", "📁 UI Screenshot/PDF Upload"])

with tab1:
    user_input_text = st.text_area("Suspicious text, email, or script paste karein:", height=150, key="text")
    analyze_text = st.button("Start AI Analysis", type="primary")

with tab2:
    user_input_url = st.text_input("Investigate direct website URL:", key="url")
    analyze_url = st.button("Fetch & Investigate URL", type="primary")
    
with tab3:
    st.info("Upload fake screenshots, UI prints, or documents for visual Dark Pattern & phishing verification.")
    uploaded_file = st.file_uploader("Upload Image or PDF:", type=['png', 'jpg', 'jpeg', 'pdf'])
    analyze_file = st.button("Analyze File Intelligently", type="primary")

# Execute Analysis
run_analysis = False
target_text = ""
target_image = None
context = "text"
domain_spoof_warnings = []

if analyze_text and user_input_text:
    target_text = user_input_text
    run_analysis = True
elif analyze_url and user_input_url:
    with st.spinner('Checking technical domain & fetching URL safely...'):
        spoofing_check = check_domain_spoofing(user_input_url)
        if spoofing_check.get("is_suspicious"):
            warnings_data = spoofing_check.get("warnings", [])
            if isinstance(warnings_data, list):
                domain_spoof_warnings = warnings_data
            
        fetched_text = fetch_text_from_url(user_input_url)
        if "Error" in fetched_text:
            st.error(fetched_text)
        else:
            target_text = fetched_text
            run_analysis = True
            context = "website URL"
elif analyze_file and uploaded_file:
    if uploaded_file.name.endswith('.pdf'):
        with st.spinner('Extracting internal data from PDF...'):
            extracted = extract_text_from_pdf(uploaded_file)
            if "Error" in extracted:
                st.error(extracted)
            else:
                target_text = extracted
                run_analysis = True
                context = "PDF Document"
    else:
        target_image = Image.open(uploaded_file)
        target_text = "Thoroughly analyze the provided UI layout, texts, and design elements within this image/screenshot to determine its true intent, explicitly checking for forced UX dark patterns."
        run_analysis = True
        context = "image/screenshot"
        st.image(target_image, caption="Visual Evidence", width=500)
elif (analyze_text and not user_input_text) or (analyze_url and not user_input_url) or (analyze_file and not uploaded_file):
    st.warning("Please provide an input target to initiate the scan.")

if run_analysis:
    with st.spinner('Zero-Day AI Reasoning Engine is active. Compiling security metrics...'):
        # 4. Ultra-Advanced Prompt with UX Dark Pattern and Full Reporting mandate
        prompt = f"""You are an elite, highly professional Cyber Security Analyst, Zero-Day Threat Hunter, and UX Security Expert. You do not just rely on known databases; you MUST use your advanced reasoning engine to deduce and predict new, never-before-seen forms of scams, phishing, and deceptive UI based on logic alone.
        
        CRITICAL MULTILINGUAL INSTRUCTION: The input may be in ANY language or script (e.g., Urdu, Roman Urdu, Arabic, French, Turkish, Persian, Chinese, Hindi, English). Detect culturally specific scams and regional phishing tactics. Provide the final report in English, but quote the original language for "Red Flags".
        
        Context of input: This is a {context}.
        
        1. Multi-Dimensional Threat Score (0-100):
           **CRITICAL**: You must exactly output `[SCORE: X]` on the very first line (where X is the number).
           - 0-30: Safe
           - 31-70: Suspicious (Warning)
           - 71-100: Dangerous (Malicious Intent)

        2. Technical & Zero-Day Analysis:
           Identify explicitly if psychological manipulation is used (Urgency, Fear, Fake Authority). Use deep logic to identify out-of-the-box manipulation attempting to bypass standard filters.

        3. UX Security & Dark Pattern Highlighter:
           Explicitly highlight ANY presence of "Dark Patterns" in the UX (e.g., Forced Continuity, Sneak into Basket, Hidden Costs, Fake Countdowns, Roach Motel, Misdirection, Confirmshaming). Explain how the user is being visually or psychologically tricked by the interface or layout.

        4. Visual/Structural Forensic Breakdown:
           Extract "Red Flags" quoting exactly from the text/image. Categorize into:
           - Blackmail/Coercion
           - Grammar/Structural Anomalies
           - Sensitive Data Probing (passwords, OTPs, seed phrases)
           - *For Visuals:* Detect fake logos, manipulated UI, design inconsistencies.

        5. Comprehensive Suggested Remediation & Next Steps:
           Provide a highly professional and concrete list of actionable suggestions specifically addressing the risks found. Tell the user EXACTLY what to do next to secure themselves or verify the authenticity.

        Format cleanly and expansively using markdown. Provide a professional, polished cybersecurity intelligence report.
        
        Input Content:
        {target_text}"""
        
        try:
            if target_image:
                response = model.generate_content([prompt, target_image])
            else:
                response = model.generate_content(prompt)
                
            result_text = response.text
            
            # Extract Score
            score_match = re.search(r'\[SCORE:\s*(\d+)\]', result_text)
            threat_score = 0
            if score_match:
                threat_score = int(score_match.group(1))
                result_text = re.sub(r'\[SCORE:\s*\d+\]', '', result_text).strip()
            
            st.divider()
            
            # Domain Spoof Alert
            if len(domain_spoof_warnings) > 0:
                st.error("🚨 **CRITICAL: Technical Domain Spoofing Detected!**")
                for w_flag in domain_spoof_warnings:
                    st.write(f"- {w_flag}")
                st.divider()
            
            # Dashboard Display
            col1, col2 = st.columns([1, 2.5])
            with col1:
                st.plotly_chart(create_gauge_chart(threat_score), use_container_width=True)
                
                # Report Downloads
                st.markdown("### 🖨️ Automated Risk Reports")
                st.info("Comprehensive zero-day analysis report ready.")
                
                spoof_data = domain_spoof_warnings if len(domain_spoof_warnings) > 0 else None
                json_report = create_json_report(threat_score, result_text, context, spoof_data)
                st.download_button(
                    label="📄 Download JSON Report (For Devs)",
                    data=json_report,
                    file_name="threat_intelligence_report.json",
                    mime="application/json",
                    use_container_width=True
                )
                
                pdf_report = create_pdf_report(threat_score, result_text, target_image, spoof_data)
                st.download_button(
                    label="📑 Download PDF Report (For Execs)",
                    data=pdf_report,
                    file_name="threat_intelligence_report.pdf",
                    mime="application/pdf",
                    use_container_width=True
                )
                
            with col2:
                st.markdown("### 🛡️ Live Security Analysis Result:")
                with st.container(border=True):
                    st.markdown(result_text)
                
        except Exception as e:
            st.error(f"Analysis failed. Please check the API key, internet connection, or file format. Debug: {e}")
