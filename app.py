import os
from flask import Flask, request, send_file, jsonify, render_template, redirect
from werkzeug.utils import secure_filename
from pymongo import MongoClient
from PyPDF2 import PdfReader, PdfWriter
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from io import BytesIO
from flask_bcrypt import Bcrypt
from dotenv import load_dotenv
import fitz  # PyMuPDF
from PIL import Image
import img2pdf
import time
import jwt  # NEW
import hashlib  # NEW
from flask_mail import Mail, Message
import random
import string
import pandas as pd

load_dotenv()
app = Flask(__name__)
app.secret_key =  os.getenv("SECRET_KEY")
bcrypt = Bcrypt(app)

UPLOAD_FOLDER = "uploads"
WATERMARKED_FOLDER = "watermarked_pdfs"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(WATERMARKED_FOLDER, exist_ok=True)

client = MongoClient(os.getenv("MONGO_URI"))
db = client.get_database("watermarkd")
users_collection = db["users"]
files_collection = db["files"]

app.config["MAIL_SERVER"] = "smtp.gmail.com"
app.config["MAIL_PORT"] = 587
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_USERNAME"] = os.getenv("EMAIL_SENDER")
app.config["MAIL_PASSWORD"] = os.getenv("EMAIL_PASSWORD")
app.config["MAIL_DEFAULT_SENDER"] = os.getenv("EMAIL_SENDER")

mail = Mail(app)

ADMIN_USERNAME = os.getenv("ADMIN_USERNAME")
ADMIN_PASSWORD = bcrypt.generate_password_hash(os.getenv("ADMIN_PASSWORD")).decode('utf-8')
if not users_collection.find_one({"username": ADMIN_USERNAME}):
    users_collection.insert_one({"username": ADMIN_USERNAME, "password": ADMIN_PASSWORD, "role": "admin"})

# Helper to get current user from JWT cookie
def get_current_user():
    token = request.cookies.get("token")
    if not token:
        return None
    try:
        payload = jwt.decode(token, app.secret_key, algorithms=["HS256"])
        return payload
    except jwt.ExpiredSignatureError:
        return None

def generate_password(length=8):
    chars = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(chars) for _ in range(length))

# Function to send email using Flask-Mail
def send_email(to_email, username, password):
    try:
        msg = Message("Your Account Credentials", recipients=[to_email])
        msg.body = f"""
        Hello,

        Your account has been created.
        Username: {username}
        Password: {password}

        Please change your password after login.

        Regards,
        Admin
        """
        mail.send(msg)
        print(f"Email sent to {to_email}")
    except Exception as e:
        print(f"Error sending email to {to_email}: {e}")

@app.route("/test_email")
def test_email():
    send_email("your_email@example.com", "testuser", "Test@1234")
    return "Email sent!"



# Route to upload Excel file and create users
@app.route("/upload_users", methods=["POST"])
def upload_users():
    current_user = request.headers.get("Admin-Token")
    if current_user != os.getenv("ADMIN_SECRET"):
        return jsonify({"error": "Unauthorized"}), 403

    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    
    file = request.files["file"]
    filename = secure_filename(file.filename)
    
    if not filename.endswith(".xlsx"):
        return jsonify({"error": "Invalid file format. Please upload an Excel file."}), 400

    df = pd.read_excel(file)
    if not {"Name", "Email ID", "Phone Number"}.issubset(df.columns):
        return jsonify({"error": "Missing required columns in Excel file"}), 400

    users_created = []
    
    for _, row in df.iterrows():

        name, email, phone = row["Name"], row["Email ID"], row["Phone Number"]

        username = email.split("@")[0]  # Generate username from email
        password = generate_password()  # Generate random password
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        if users_collection.find_one({"email": email}):
            continue
            
        
        users_collection.insert_one({
            "name": name,
            "email": email,
            "username": username,
            "phone": phone,
            "password": hashed_password,
            "role": "user"
        })

        send_email(email, username, password)
        users_created.append(email)

    return jsonify({"message": f"Users created successfully: {len(users_created)}"}), 201


@app.route("/logins", methods=["POST"])
def login():
    data = request.json
    username = data.get("username")
    password = data.get("password")
    user = users_collection.find_one({"username": username})
    
    if user and bcrypt.check_password_hash(user["password"], password):
        # If a valid token already exists, reject duplicate logins
        if get_current_user():
            return jsonify({"error": "Already logged in"}), 400
        if user.get("role") == "admin":
            return jsonify({"error": "Invalid credentials"}), 401
        token = jwt.encode({
            "username": user["username"],
            "role": user.get("role", "user")
        }, app.secret_key, algorithm="HS256")
        user_data = {
            "username": user["username"],
            "role": user.get("role", "user"),
            "name": user.get("name"),
            "email": user.get("email")
        }
        response = jsonify({"message": "Login successful", "data": user_data, "role": user.get("role"), "token": token})
        response.set_cookie("token", token)
        return response
    return jsonify({"error": "Invalid credentials"}), 401

@app.route("/adm-login", methods=["POST"])
def admlogin():
    data = request.json
    username = data.get("username")
    password = data.get("password")
    user = users_collection.find_one({"username": username})
    
    if user and bcrypt.check_password_hash(user["password"], password):
        if get_current_user():
            return jsonify({"error": "Already logged in"}), 400
        if user.get("role") == "user":
            return jsonify({"error": "Invalid credentials"}), 401
        token = jwt.encode({
            "username": user["username"],
            "role": user.get("role", "admin")
        }, app.secret_key, algorithm="HS256")
        user_data = {
            "username": user["username"],
            "role": user.get("role", "admin"),
            "name": user.get("name"),
            "email": user.get("email")
        }
        response = jsonify({"message": "Login successful", "data": user_data, "role": user.get("role"), "token": token})
        response.set_cookie("token", token)
        return response
    return jsonify({"error": "Invalid credentials"}), 401

@app.route("/upload", methods=["POST"])
def upload_pdf():
    current_user = get_current_user()
    if not current_user or current_user.get("role") != "admin":
        return jsonify({"error": "Only admin can upload files"}), 403
    if "file" not in request.files:
        return jsonify({"error": "No file part"}), 400
    
    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "No selected file"}), 400
    
    filename = secure_filename(file.filename)
    file_path = os.path.join(UPLOAD_FOLDER, filename)

    # Check if file already exists with same name and content
    if os.path.exists(file_path):
        new_contents = file.read()
        new_hash = hashlib.md5(new_contents).hexdigest()
        file.seek(0)  # reset file pointer
        with open(file_path, "rb") as existing_file:
            existing_hash = hashlib.md5(existing_file.read()).hexdigest()
        if new_hash == existing_hash:
            return jsonify({"error": "File already uploaded"}), 400

    file.save(file_path)
    
    files_collection.insert_one({"filename": filename, "uploaded_by": os.getenv("ADMIN_USERNAME")})
    return jsonify({"message": "File uploaded successfully", "filename": filename})

@app.route("/files", methods=["GET"])
def list_files():
    if not get_current_user():
        return jsonify({"error": "Unauthorized"}), 403
    # Only include files uploaded by admin
    admin_files = list(files_collection.find({"uploaded_by": os.getenv("ADMIN_USERNAME")}, {"_id": 0, "filename": 1}))
    return jsonify({"files": admin_files})

def add_watermark(input_pdf_path, output_pdf_path, username):
    # Create a watermark
    watermark_pdf = BytesIO()
    c = canvas.Canvas(watermark_pdf, pagesize=letter)
    c.setFont("Helvetica", 50)
    c.setFillColorRGB(0.7, 0.7, 0.7, 0.4)  # Light gray with transparency
    c.translate(300, 320)
    c.rotate(30)
    c.drawString(0, 0, username)
    c.save()

    watermark_pdf.seek(0)
    watermark_reader = PdfReader(watermark_pdf)
    watermark_page = watermark_reader.pages[0]

    # Read the original PDF
    reader = PdfReader(input_pdf_path)
    writer = PdfWriter()

    for page in reader.pages:
        page.merge_page(watermark_page)
        writer.add_page(page)

    temp_pdf_path = output_pdf_path.replace(".pdf", "_temp.pdf")

    with open(temp_pdf_path, "wb") as temp_pdf:
        writer.write(temp_pdf)

    # Convert watermarked PDF to images using PyMuPDF
    doc = fitz.open(temp_pdf_path)
    images = []
    temp_dir = "temp_images"
    os.makedirs(temp_dir, exist_ok=True)

    for page_num in range(len(doc)):
        img_path = os.path.join(temp_dir, f"page_{page_num}.png")
        pix = doc[page_num].get_pixmap()  # Convert page to an image
        img = Image.frombytes("RGB", [pix.width, pix.height], pix.samples)
        img.save(img_path, "PNG")
        images.append(img_path)

    doc.close()

    # Convert images back to a non-editable PDF
    with open(output_pdf_path, "wb") as final_pdf:
        final_pdf.write(img2pdf.convert(images))

    time.sleep(1)

    try:
        os.remove(temp_pdf_path)  # Delete temp PDF after closing it
    except PermissionError:
        print(f"Warning: Unable to delete {temp_pdf_path}, skipping...")

    for img in images:
        os.remove(img)
    os.rmdir(temp_dir)

@app.route("/download/<filename>", methods=["GET"])
def download_pdf(filename):
    current_user = get_current_user()
    if not current_user or current_user.get("role") != "user":
        return jsonify({"error": "Unauthorized"}), 403
    
    input_pdf_path = os.path.join(UPLOAD_FOLDER, filename)
    if not os.path.exists(input_pdf_path):
        return jsonify({"error": "File not found"}), 404
    
    output_pdf_path = os.path.join(WATERMARKED_FOLDER, f"{current_user['username']}_{filename}")
    add_watermark(input_pdf_path, output_pdf_path, current_user['username'])
    
    return send_file(output_pdf_path, as_attachment=True)

@app.route("/uploads/<filename>", methods=["GET"])
def get_uploaded_file(filename):
    if not get_current_user():
        return jsonify({"error": "Unauthorized"}), 403
    
    file_path = os.path.join(UPLOAD_FOLDER, filename)
    if not os.path.exists(file_path):
        return jsonify({"error": "File not found"}), 404
    
    return send_file(file_path)

@app.route("/delete/<filename>", methods=["DELETE"])
def delete_file(filename):
    current_user = get_current_user()
    if not current_user or current_user.get("role") != "admin":
        return jsonify({"error": "Unauthorized"}), 403

    # Delete file from the uploads folder
    
    file_path = os.path.join(UPLOAD_FOLDER, filename)
    if os.path.exists(file_path):
        try:
            os.remove(file_path)
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    else:
        return jsonify({"error": "File not found in uploads"}), 404

    # Delete file record from the database
    result = files_collection.delete_one({"filename": filename})
    if result.deleted_count == 0:
        return jsonify({"error": "File record not found in database"}), 404

    return jsonify({"message": "File deleted successfully"})




@app.route("/logout", methods=["POST"])
def logout():
    response = jsonify({"message": "Logged out successfully"})
    response.delete_cookie("token")
    return response

@app.route("/")
def home():
    return render_template("home.html", current_user=get_current_user())
@app.route("/about")
def about():
    return render_template("about.html", current_user=get_current_user())

@app.route("/login")
def login_page():
    if get_current_user():
        user = get_current_user()
        if user.get("role") == "user":
            return redirect("/user_files")
        elif user.get("role") == "admin":
            return redirect("/admin")
    return render_template("login.html", current_user=None)



@app.route("/admin_login")
def admin_login_page():
    if get_current_user():
        user = get_current_user()
        if user.get("role") == "user":
            return redirect("/user_files")
        elif user.get("role") == "admin":
            return redirect("/admin")
    return render_template("admin_login.html", current_user=None)

@app.route("/admin")
def admin():
    current_user = get_current_user()
    if (current_user and current_user.get("role") == "user") or (not current_user) or (current_user.get("role") != "admin"):
        return redirect("/admin_login")
    return render_template("admin.html", current_user=current_user)

@app.route("/user_files")
def user_files():
    current_user = get_current_user()
    if (current_user and current_user.get("role") == "admin") or (not current_user) or (current_user.get("role") != "user"):
        return redirect("/logins")
    return render_template("user_files.html", current_user=current_user)

@app.route("/admin_create_user")
def admin_create_user():
    current_user = get_current_user()
    if (current_user and current_user.get("role") == "user") or (not current_user) or (current_user.get("role") != "admin"):
        return redirect("/admin_login")
    return render_template("admin_create_user.html", current_user=current_user)

@app.route("/admin_upload")
def admin_upload_file():
    current_user = get_current_user()
    if (current_user and current_user.get("role") == "user") or (not current_user) or (current_user.get("role") != "admin"):
        return redirect("/admin_login")
    return render_template("admin_upload_file.html", current_user=current_user)

if __name__ == "__main__":
    app.run(debug=True)
