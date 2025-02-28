import os
from flask import Flask, request, send_file, jsonify, render_template, redirect, after_this_request
from werkzeug.utils import secure_filename
import mysql.connector
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
import jwt
import hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed
import pandas as pd
from email_stepup import send_email
import random
import string
import base64
import threading

load_dotenv(override=True)
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")
bcrypt = Bcrypt(app)

UPLOAD_FOLDER = "uploads"
WATERMARKED_FOLDER = "watermarked_pdfs"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(WATERMARKED_FOLDER, exist_ok=True)

# MySQL connection
db_config = {
    "host": "srv1824.hstgr.io",
    "user": "u145695899_UdaanByRobot",
    "password": "UdaanByRobot2025Upsc",
    "database": "u145695899_Udaan"
}

def get_db_connection():
    return mysql.connector.connect(**db_config)

ADMIN_USERNAME = os.getenv("ADMIN_NAME")
ADMIN_PASSWORD = os.getenv("ADMIN_PASS")

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

@app.route("/logins", methods=["POST"])
def login():
    data = request.json
    username = data.get("username")
    password = data.get("password")
    
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
    user = cursor.fetchone()
    conn.close()
    
    if user and bcrypt.check_password_hash(user["password"], password):
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
        response = jsonify({"message": "Login successful", "data": user_data, "role": user["role"], "token": token})
        response.set_cookie("token", token)
        return response
    return jsonify({"error": "Invalid credentials"}), 401

@app.route("/adm-login", methods=["POST"])
def admlogin():
    data = request.json
    username = data.get("username")
    password = data.get("password")
    if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
        if get_current_user():
            return jsonify({"error": "Already logged in"}), 400
        token = jwt.encode({
            "username": ADMIN_USERNAME,
            "role": "admin"
        }, app.secret_key, algorithm="HS256")
        user_data = {
            "username": ADMIN_USERNAME,
            "role": "admin"
        }
        response = jsonify({"message": "Login successful", "data": user_data, "role": "admin", "token": token})
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

    if os.path.exists(file_path):
        new_contents = file.read()
        new_hash = hashlib.md5(new_contents).hexdigest()
        file.seek(0)
        with open(file_path, "rb") as existing_file:
            existing_hash = hashlib.md5(existing_file.read()).hexdigest()
        if new_hash == existing_hash:
            return jsonify({"error": "File already uploaded"}), 400

    file.save(file_path)
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO files (filename, uploaded_by, demo_type) VALUES (%s, %s, %s)",
        (filename, os.getenv("ADMIN_USERNAME"), False)
    )
    conn.commit()
    conn.close()
    return jsonify({"message": "File uploaded successfully", "filename": filename})

@app.route("/files", methods=["GET"])
def list_files():
    if not get_current_user():
        return jsonify({"error": "Unauthorized"}), 403
    
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    cursor.execute("SELECT filename, demo_type FROM files")  # Fetch all files
    
    all_files = cursor.fetchall()
    print(all_files)  # Debugging output
    
    conn.close()
    return jsonify({"files": all_files})


def add_watermark(input_pdf_path, output_pdf_path, username):
    watermark_pdf = BytesIO()
    c = canvas.Canvas(watermark_pdf, pagesize=letter)
    c.setFont("Helvetica", 50)
    c.setFillColorRGB(0.7, 0.7, 0.7, 0.4)
    c.translate(300, 320)
    c.rotate(30)
    c.drawString(0, 0, username)
    c.save()

    watermark_pdf.seek(0)
    watermark_reader = PdfReader(watermark_pdf)
    watermark_page = watermark_reader.pages[0]

    reader = PdfReader(input_pdf_path)
    writer = PdfWriter()

    for page in reader.pages:
        page.merge_page(watermark_page)
        writer.add_page(page)

    temp_pdf_path = output_pdf_path.replace(".pdf", "_temp.pdf")
    with open(temp_pdf_path, "wb") as temp_pdf:
        writer.write(temp_pdf)

    doc = fitz.open(temp_pdf_path)
    images = []
    temp_dir = "temp_images"
    os.makedirs(temp_dir, exist_ok=True)

    for page_num in range(len(doc)):
        img_path = os.path.join(temp_dir, f"page_{page_num}.png")
        pix = doc[page_num].get_pixmap()
        img = Image.frombytes("RGB", [pix.width, pix.height], pix.samples)
        img.save(img_path, "PNG")
        images.append(img_path)

    doc.close()

    with open(output_pdf_path, "wb") as final_pdf:
        final_pdf.write(img2pdf.convert(images))

    time.sleep(1)

    try:
        os.remove(temp_pdf_path)
    except PermissionError:
        print(f"Warning: Unable to delete {temp_pdf_path}, skipping...")

    for img in images:
        os.remove(img)
    os.rmdir(temp_dir)

def delete_file_later(file_path, delay=20):
    def delayed_deletion():
        time.sleep(delay)
        try:
            os.remove(file_path)
            print(f"Deleted file: {file_path}")
        except Exception as e:
            print(f"Error deleting file: {e}")
    threading.Thread(target=delayed_deletion, daemon=True).start()

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

    response = send_file(output_pdf_path, as_attachment=True)
    
    @after_this_request
    def remove_file(response):
        delete_file_later(output_pdf_path)
        return response

    return response

@app.route("/uploads/<filename>", methods=["GET"])
def get_uploaded_file(filename):
    file_path = os.path.join(UPLOAD_FOLDER, filename)
    if not os.path.exists(file_path):
        return jsonify({"error": "File not found"}), 404
    return send_file(file_path)

@app.route("/delete/<filename>", methods=["DELETE"])
def delete_file(filename):
    current_user = get_current_user()
    if not current_user or current_user.get("role") != "admin":
        return jsonify({"error": "Unauthorized"}), 403

    file_path = os.path.join(UPLOAD_FOLDER, filename)
    if os.path.exists(file_path):
        try:
            os.remove(file_path)
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM files WHERE filename = %s", (filename,))
    conn.commit()
    if cursor.rowcount == 0:
        conn.close()
        return jsonify({"error": "File record not found in database"}), 404
    conn.close()
    return jsonify({"message": "File deleted successfully"})

@app.route("/set_demo/<filename>", methods=["POST"])
def set_demo_type(filename):
    current_user = get_current_user()
    if not current_user or current_user.get("role") != "admin":
        return jsonify({"error": "Only admin can change demo type status"}), 403

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT demo_type FROM files WHERE filename = %s", (filename,))
    file = cursor.fetchone()
    if not file:
        conn.close()
        return jsonify({"error": "File not found"}), 404

    new_demo_type = not file["demo_type"]
    cursor.execute(
        "UPDATE files SET demo_type = %s WHERE filename = %s",
        (new_demo_type, filename)
    )
    conn.commit()
    conn.close()
    return jsonify({"demo_type": new_demo_type, "message": f"Demo type status set to {new_demo_type} for {filename}"})

@app.route("/logout", methods=["POST"])
def logout():
    response = jsonify({"message": "Logged out successfully"})
    response.delete_cookie("token")
    return response

@app.route("/api/testimonials", methods=["GET"])
def get_testimonials():
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT name, image, description FROM testimonials")
        testimonials = cursor.fetchall()
        conn.close()
        return jsonify({"testimonials": testimonials})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/testimonials", methods=["POST"])
def add_testimonial():
    try:
        data = request.form
        name = data.get("name")
        description = data.get("description")
        image_url = data.get("image_url")
        image_file = request.files.get("image_file")

        if not all([name, description]) or (not image_url and not image_file):
            return jsonify({"error": "All fields are required"}), 400

        if image_file:
            image = base64.b64encode(image_file.read()).decode('utf-8')
        else:
            image = image_url

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO testimonials (name, image, description) VALUES (%s, %s, %s)",
            (name, image, description)
        )
        conn.commit()
        conn.close()
        return jsonify({"message": "Testimonial added successfully"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/testimonials/<name>", methods=["DELETE"])
def delete_testimonial(name):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM testimonials WHERE name = %s", (name,))
        conn.commit()
        if cursor.rowcount == 0:
            conn.close()
            return jsonify({"error": "Testimonial not found"}), 404
        conn.close()
        return jsonify({"message": "Testimonial deleted successfully"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/upload_testimonial")
def upload_testimonial_page():
    current_user = get_current_user()
    if not current_user or current_user.get("role") != "admin":
        return redirect("/admin_login")
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT name, image, description FROM testimonials")
    testimonials = cursor.fetchall()
    conn.close()
    return render_template("upload_testimonial.html", current_user=current_user, testimonials=testimonials)

@app.route("/")
def home():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT name, image, description FROM testimonials")
    testimonials = cursor.fetchall()
    conn.close()
    return render_template("home.html", current_user=get_current_user(), testimonials=testimonials)

@app.route("/about")
def about():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT name, image, description FROM testimonials")
    testimonials = cursor.fetchall()
    conn.close()
    return render_template("about.html", current_user=get_current_user(), testimonials=testimonials)

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

def generate_unique_username(base_username):
    while True:
        username = f"udaan_{base_username}_{random.randint(1000, 9999)}"
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM users WHERE username = %s", (username,))
        if cursor.fetchone()[0] == 0:
            conn.close()
            return username
        conn.close()

def generate_random_password(length=8):
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(characters) for i in range(length))

@app.route('/send-emails', methods=['POST'])
def send_bulk_emails():
    try:
        current_user = get_current_user()
        if not current_user or current_user.get("role") != "admin":
            return jsonify({"error": "Only admin can upload Excel files"}), 403
        if "excel_file" not in request.files:
            return jsonify({"error": "No file part"}), 400
        excel_file = request.files["excel_file"]
        if excel_file.filename == "":
            return jsonify({"error": "No selected file"}), 400

        filename = secure_filename(excel_file.filename)
        file_path = os.path.join(UPLOAD_FOLDER, filename)
        excel_file.save(file_path)

        df = pd.read_excel(file_path)
        df.columns = df.columns.str.lower()

        results = []
        conn = get_db_connection()
        cursor = conn.cursor()
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = []
            for _, row in df.iterrows():
                cursor.execute("SELECT COUNT(*) FROM users WHERE email = %s", (row["email"],))
                if cursor.fetchone()[0] > 0:
                    results.append(f"Email {row['email']} already exists.")
                    continue
                base_username = row["email"].split("@")[0]
                username = generate_unique_username(base_username)
                password = generate_random_password()
                hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
                cursor.execute(
                    "INSERT INTO users (name, email, username, password, role) VALUES (%s, %s, %s, %s, %s)",
                    (row["name"], row["email"], username, hashed_password, "user")
                )
                conn.commit()
                futures.append(executor.submit(send_email, row["email"], username, password))
            for future in as_completed(futures):
                results.append(future.result())
        conn.close()

        os.remove(file_path)
        return jsonify({"message": "Emails sent successfully!", "details": results})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/create_user', methods=['POST'])
def create_user():
    try:
        current_user = get_current_user()
        if not current_user or current_user.get("role") != "admin":
            return jsonify({"error": "Only admin can create users"}), 403
            
        data = request.json
        name = data.get("name")
        email = data.get("email")
        base_username = email.split("@")[0]

        if not all([name, email]):
            return jsonify({"error": "All fields are required"}), 400

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM users WHERE email = %s", (email,))
        if cursor.fetchone()[0] > 0:
            conn.close()
            return jsonify({"error": "Email already exists"}), 400
            
        password = generate_random_password()
        username = generate_unique_username(base_username)
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        cursor.execute(
            "INSERT INTO users (name, email, username, password, role) VALUES (%s, %s, %s, %s, %s)",
            (name, email, username, hashed_password, "user")
        )
        conn.commit()
        conn.close()
            
        send_email(email, username, password)
        return jsonify({"message": "User created successfully and email sent!"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/test-series")
def test_series():
    current_user = get_current_user()
    return render_template("test_series.html", current_user=current_user)

@app.route("/demo-files", methods=["GET"])
def list_demo_files():
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT filename, demo_type FROM files WHERE demo_type = TRUE")
        demo_files = cursor.fetchall()
        conn.close()
        return jsonify({"files": demo_files})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/admin_testimonials")
def admin_testimonials():
    current_user = get_current_user()
    if not current_user or current_user.get("role") != "admin":
        return redirect("/admin_login")
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT name, image, description FROM testimonials")
    testimonials = cursor.fetchall()
    conn.close()
    return render_template("upload_testimonial.html", current_user=current_user, testimonials=testimonials)

if __name__ == "__main__":
    app.run(debug=True)