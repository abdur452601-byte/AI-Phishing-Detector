import streamlit as st
import pandas as pd
from sklearn.naive_bayes import MultinomialNB
import os
import re
from urllib.parse import urlparse

# --- 1. AI EMAIL MODEL (Cached so it only trains once) ---
@st.cache_resource
def load_and_train_model():
    file_path = os.path.join('data', 'emails.csv')
    try:
        df = pd.read_csv(file_path)
    except FileNotFoundError:
        return None, None

    word_columns = df.columns[1:-1]
    X = df[word_columns]
    y = df['Prediction']

    model = MultinomialNB()
    model.fit(X, y)
    
    return model, word_columns

model, word_columns = load_and_train_model()

# --- 2. URL CHECKER LOGIC ---
def check_url_safety(url):
    suspicious_score = 0
    reasons = []

    # Check 1: IP Address in URL (Phishers do this to hide domain names)
    if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url):
        suspicious_score += 40
        reasons.append("Contains an IP address instead of a domain name.")

    # Check 2: The '@' symbol (Browsers ignore everything before '@')
    if '@' in url:
        suspicious_score += 30
        reasons.append("Contains an '@' symbol, often used to spoof legitimate sites.")

    # Check 3: Unusual length
    if len(url) > 75:
        suspicious_score += 15
        reasons.append("URL is unusually long (common in phishing).")

    # Check 4: Suspicious keywords
    suspicious_words = ['login', 'verify', 'update', 'secure', 'account', 'banking', 'free']
    for word in suspicious_words:
        if word in url.lower():
            suspicious_score += 10
            reasons.append(f"Contains suspicious keyword: '{word}'.")

    # Check 5: HTTPS vs HTTP
    if not url.startswith("https://"):
        suspicious_score += 10
        reasons.append("Does not use secure HTTPS encryption.")

    return suspicious_score, reasons

# --- 3. STREAMLIT UI ---
st.set_page_config(page_title="Phishing Detector", page_icon="🛡️", layout="centered")

st.title("🛡️ AI Phishing & URL Detector")
st.write("Welcome! Use the tabs below to check emails for spam or scan URLs for phishing threats.")

# Create tabs for the UI
tab1, tab2 = st.tabs(["📧 Email Checker", "🔗 URL Checker"])

# --- EMAIL TAB ---
with tab1:
    st.subheader("Analyze Email Content")
    email_input = st.text_area("Paste the email text here:", height=200)
    
    if st.button("Check Email", type="primary"):
        if not email_input.strip():
            st.warning("Please paste an email first.")
        elif model is None:
            st.error("Error: Could not load the AI model. Is emails.csv in the data folder?")
        else:
            # Process text and predict
            words_in_input = re.findall(r'\b\w+\b', email_input.lower())
            input_data = {word: 0 for word in word_columns}
            
            for word in words_in_input:
                if word in input_data:
                    input_data[word] += 1
                    
            input_df = pd.DataFrame([input_data])
            prediction = model.predict(input_df)
            
            if prediction[0] == 1:
                st.error("🚨 **WARNING: This email looks like a PHISHING/SPAM attempt!**")
            else:
                st.success("✅ **SAFE: This email appears to be legitimate.**")

# --- URL TAB ---
with tab2:
    st.subheader("Scan a Web Link")
    url_input = st.text_input("Paste the URL here (e.g., http://example.com):")
    
    if st.button("Check URL", type="primary"):
        if not url_input.strip():
            st.warning("Please paste a URL first.")
        else:
            score, reasons = check_url_safety(url_input)
            
            if score >= 30:
                st.error(f"🚨 **DANGER: This URL is highly suspicious (Risk Score: {score}/100)**")
                for reason in reasons:
                    st.write(f"- {reason}")
            elif score > 0:
                st.warning(f"⚠️ **CAUTION: This URL has some suspicious traits (Risk Score: {score}/100)**")
                for reason in reasons:
                    st.write(f"- {reason}")
            else:
                st.success("✅ **SAFE: No obvious phishing traits detected in this URL.**")