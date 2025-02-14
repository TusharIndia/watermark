import os
from flask import Flask, request, send_file, jsonify, session, render_template, redirect
from werkzeug.utils import secure_filename
from pymongo import MongoClient
from PyPDF2 import PdfReader, PdfWriter
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from io import BytesIO
from flask_bcrypt import Bcrypt
from flask_session import Session
from dotenv import load_dotenv

import fitz  # PyMuPDF
from PIL import Image
import img2pdf
import time


load_dotenv()
app = Flask(__name__)
app.secret_key =  os.getenv("SECRET_KEY")
app.config["SESSION_TYPE"] = "filesystem"
Session(app)
bcrypt = Bcrypt(app)

UPLOAD_FOLDER = "uploads"
WATERMARKED_FOLDER = "watermarked_pdfs"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(WATERMARKED_FOLDER, exist_ok=True)

client = MongoClient(os.getenv("MONGO_URI"))
db = client.get_database("watermarkd")
users_collection = db["users"]
files_collection = db["files"]

ADMIN_USERNAME = os.getenv("ADMIN_USERNAME")
ADMIN_PASSWORD = bcrypt.generate_password_hash(os.getenv("ADMIN_PASSWORD")).decode('utf-8')
if not users_collection.find_one({"username": ADMIN_USERNAME}):
    users_collection.insert_one({"username": ADMIN_USERNAME, "password": ADMIN_PASSWORD, "role": "admin"})

@app.route("/create_user", methods=["POST"])
def create_user():
    if "username" not in session or session["username"] != ADMIN_USERNAME:
        return jsonify({"error": "Unauthorized"}), 403
    
    data = request.json
    username = data.get("username")
    password = bcrypt.generate_password_hash(data.get("password")).decode('utf-8')
    
    if users_collection.find_one({"username": username}):
        return jsonify({"error": "User already exists"}), 400
    
    users_collection.insert_one({"name":data.get("name"),"email":data.get("email"),"username": username, "password": password, "role": "user"})
    return jsonify({"message": "User created successfully"})

@app.route("/login", methods=["POST"])
def login():
    data = request.json
    username = data.get("username")
    password = data.get("password")
    user = users_collection.find_one({"username": username})
    
    if user and bcrypt.check_password_hash(user["password"], password):
        session["username"] = username
        session["role"] = user.get("role", "user")
        return jsonify({"message": "Login successful", "role": session["role"]})
    return jsonify({"error": "Invalid credentials"}), 401

@app.route("/upload", methods=["POST"])
def upload_pdf():
    if "username" not in session or session.get("role") != "admin":
        return jsonify({"error": "Only admin can upload files"}), 403
    if "file" not in request.files:
        return jsonify({"error": "No file part"}), 400
    
    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "No selected file"}), 400
    
    filename = secure_filename(file.filename)
    file_path = os.path.join(UPLOAD_FOLDER, filename)
    file.save(file_path)
    
    files_collection.insert_one({"filename": filename, "uploaded_by": session["username"]})
    return jsonify({"message": "File uploaded successfully", "filename": filename})

@app.route("/files", methods=["GET"])
def list_files():
    if "username" not in session:
        return jsonify({"error": "Unauthorized"}), 403
    # Only include files uploaded by admin
    admin_files = list(files_collection.find({"uploaded_by": ADMIN_USERNAME}, {"_id": 0, "filename": 1}))
    return jsonify({"files": admin_files})

def add_watermark(input_pdf_path, output_pdf_path, username):
    # Create a watermark
    watermark_pdf = BytesIO()
    c = canvas.Canvas(watermark_pdf, pagesize=letter)
    c.setFont("Helvetica", 50)
    c.setFillColorRGB(0.7, 0.7, 0.7, 0.3)  # Light gray with transparency
    c.translate(300, 400)
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
    if "username" not in session or session.get("role") != "user":
        return jsonify({"error": "Unauthorized"}), 403
    
    input_pdf_path = os.path.join(UPLOAD_FOLDER, filename)
    if not os.path.exists(input_pdf_path):
        return jsonify({"error": "File not found"}), 404
    
    output_pdf_path = os.path.join(WATERMARKED_FOLDER, f"{session['username']}_{filename}")
    add_watermark(input_pdf_path, output_pdf_path, session['username'])
    
    return send_file(output_pdf_path, as_attachment=True)

@app.route("/logout", methods=["POST"])
def logout():
    session.pop("username", None)
    session.pop("role", None)
    return jsonify({"message": "Logged out successfully"})

@app.route("/")
def home():
    return render_template("home.html")

@app.route("/login")
def login_page():
    return render_template("login.html")

@app.route("/signup")
def signup_page():
    return redirect("/login")

# Removed the converter route completely
# @app.route("/converter")
# def converter_page():
#     if "username" not in session:
#         return redirect("/login")
#     return render_template("converter.html")

@app.route("/admin_login")
def admin_login_page():
    return render_template("admin_login.html")

@app.route("/admin")
def admin():
    if "username" not in session or session.get("role") != "admin":
        return redirect("/admin_login")
    return render_template("admin.html")

@app.route("/user_files")
def user_files():
    if "username" not in session or session.get("role") != "user":
        return redirect("/login")
    return render_template("user_files.html")

@app.route("/admin_create_user")
def admin_create_user():
    if "username" not in session or session.get("role") != "admin":
        return redirect("/admin_login")
    return render_template("admin_create_user.html")

@app.route("/admin_upload")
def admin_upload_file():
    if "username" not in session or session.get("role") != "admin":
        return redirect("/admin_login")
    return render_template("admin_upload_file.html")

if __name__ == "__main__":
    app.run(debug=True)
