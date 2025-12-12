import streamlit as st
import requests
from bs4 import BeautifulSoup
import ssl

st.set_page_config(page_title="Web Security Scanner", layout="wide")
st.title("WEB SECURITY SCANNER")
st.write("Enetr the URL to check for scanning common issues.")
url=st.text_input("Enter URL (Ex: https://example.com)")

sql_payloads = ["'", "\"", "' OR 1=1--", "\" OR 1=1--", "';", "' OR '1'='1"]


def test_sql_injection(base_url):
    results=[]
    for i in sql_payloads:
        try:
            test_url=base_url+i
            res=requests.get(test_url, timeout=5)
            errors=["mysql","syntax error","sql error","warning","Unclosed quotes"]

        except:
            pass
    return results if results else ["No SQL Injection symptoms detected."]

xss_payloads = [
    "<script>alert('XSS');</script>",
    "<script>alert(document.cookie);</script>",
    "<img src=x onerror=alert('XSS')>"
]


def test_xss(base_url):
    results=[]
    for payload in xss_payloads:
        try:
            test_url=base_url+payload
            res=requests.get(test_url, timeout=5)
            if payload in res.text:
                results.append(f"Possible payload found: {payload}") 
        except:
            pass
    return results if results else ["No XSS symptoms detected."]
required=[
    "Content-Security-Policy",
    "Xss-Protection",
    "X-Frame-Policy",
    "Strict-Transport-Security"
]

def check_headers(base_url):
    missing=[]
    try:
        res=requests.get(base_url, timeout=5)
        headers = res.headers
        for h in required:
            if h not in headers:
                missing.append(f"Missing security header: {h}")
    except:
        return ["Unable to fetch headers."]
    return missing if missing else ["All essential security headers are present."]

# 4  Checking HTTPS

def check_https(base_url):
    if base_url.startswith("https://"):
        return "HTTPS Enaled"
    else:
        return "HTTPS Not Enabled"


# 5.Directory Endpoints


comman_path=[
    "/login","/admin","/dashboard","/config","/setup"
]

def scan_directories(base_url):
    found=[]