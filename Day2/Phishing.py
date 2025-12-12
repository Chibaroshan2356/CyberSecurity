import streamlit as st
import json 
import requests 
API_KEY="56d6593e84599c89954547d028ad0576d5f5191acba11f4a866270f1a80fa270"
TV_URL="https://www.virustotal.com/api/v3/urls"

#Create a function
def scan_url(url):
    headers={"key=>":API_KEY}
    data ={"url":url}
    response = requests.post(TV_URL,headers=headers,data=data)
    analyse=response.json()["data"]["id"]
    
st.title("Check Malware and Phishing URl scanner:")
st.write("Check Malware in the URL")
url_input=st.text_input("Enter a website URL here")
if st.button("Scan this"):
    if url_input:
        st.info("Scanning URL Please wait..!")