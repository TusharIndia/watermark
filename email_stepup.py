from flask import Flask, jsonify
import pandas as pd
import smtplib
import base64
import requests
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os
app = Flask(__name__)


# Gmail SMTP Configuration
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
SENDER_EMAIL = os.getenv('SENDER_EMAIL')  # Replace with your Gmail

def get_access_token():
    """Fetch a new OAuth access token using the refresh token"""
    url = "https://oauth2.googleapis.com/token"
    data = {
        "client_id": os.getenv("CLIENT_ID"),
        "client_secret": os.getenv("CLIENT_SECRET"),
        "refresh_token": os.getenv("REFRESH_TOKEN"),
        "grant_type": "refresh_token"
    }

    response = requests.post(url, data=data)
    if response.status_code == 200:
        return response.json()["access_token"]
    else:
        raise Exception(f"Failed to get access token: {response.text}")

def load_email_template(username, password):
    """Load HTML email template and insert user credentials."""
    with open("./templates/email_template.html", "r", encoding="utf-8") as file:
        template = file.read()
    
    return (template.replace("{username}", str(username)).replace("{password}",str(password) ))

def send_email(to_email, username, password):
    """Send an email using Gmail SMTP with OAuth 2.0"""
    try:
        access_token = get_access_token()

        # Email subject
        subject = "Welcome to Udaan UPSC – Your Login Credentials"

        # HTML Email Body
        body =  load_email_template(username, password)
        # Create email message
        msg = MIMEMultipart()
        msg["From"] = SENDER_EMAIL
        msg["To"] = to_email
        msg["Subject"] = subject
        msg.attach(MIMEText(body, "html"))  # Send email as HTML

        # Connect to Gmail SMTP server using OAuth 2.0
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        auth_string = f"user={SENDER_EMAIL}\x01auth=Bearer {access_token}\x01\x01"
        server.docmd("AUTH", f"XOAUTH2 {base64.b64encode(auth_string.encode()).decode()}")
        server.sendmail(SENDER_EMAIL, to_email, msg.as_string())
        server.quit()

        return f"Email sent to {to_email}"

    except Exception as e:
        return f"Failed to send email to {to_email}. Error: {str(e)}"
