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
from concurrent.futures import ThreadPoolExecutor, as_completed  # added import
import pandas as pd  # added import
from email_stepup import send_email
import random
import string
import base64  # added import


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
testimonials_collection = db["testimonials"]


ADMIN_USERNAME = os.getenv("ADMIN_USERNAME")
ADMIN_PASSWORD = bcrypt.generate_password_hash(os.getenv("ADMIN_PASSWORD")).decode('utf-8')

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






# Route to upload Excel file and create users
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
   
    if username == ADMIN_USERNAME and bcrypt.check_password_hash(ADMIN_PASSWORD, password):
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
    
    files_collection.insert_one({"filename": filename, "uploaded_by": os.getenv("ADMIN_USERNAME") , "demo_type":False})
    return jsonify({"message": "File uploaded successfully", "filename": filename})

@app.route("/files", methods=["GET"])
def list_files():
    if not get_current_user():
        return jsonify({"error": "Unauthorized"}), 403
    # Only include files uploaded by admin
    admin_files = list(files_collection.find({"uploaded_by": os.getenv("ADMIN_USERNAME")}, {"_id": 0, "filename": 1 , "demo_type":1}))
    
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
    
    response = send_file(output_pdf_path, as_attachment=True)
    
    @response.call_on_close
    def remove_file():
        try:
            os.remove(output_pdf_path)
        except Exception as e:
            print(f"Error deleting file: {e}")
    
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

@app.route("/set_demo/<filename>", methods=["POST"])
def set_demo_type(filename):
    current_user = get_current_user()
    if not current_user or current_user.get("role") != "admin":
        return jsonify({"error": "Only admin can change demo type status"}), 403

    file = files_collection.find_one({"filename": filename})
    if not file:
        return jsonify({"error": "File not found"}), 404

    new_demo_type = not file.get("demo_type", False)
    result = files_collection.update_one(
        {"filename": filename},
        {"$set": {"demo_type": new_demo_type}}
    )

    if result.matched_count == 0:
        return jsonify({"error": "File not found"}), 404

    return jsonify({"demo_type": new_demo_type,"message": f"Demo type status set to {new_demo_type} for {filename}" })

@app.route("/logout", methods=["POST"])
def logout():
    response = jsonify({"message": "Logged out successfully"})
    response.delete_cookie("token")
    return response

# API to get testimonials
@app.route("/api/testimonials", methods=["GET"])
def get_testimonials():
    try:
        testimonials = list(testimonials_collection.find({}, {"_id": 0}))
        return jsonify({"testimonials": testimonials})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# API to add a testimonial
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

        testimonial = {
            "name": name,
            "image": image,
            "description": description
        }
        testimonials_collection.insert_one(testimonial)
        return jsonify({"message": "Testimonial added successfully"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# API to delete a testimonial
@app.route("/api/testimonials/<name>", methods=["DELETE"])
def delete_testimonial(name):
    try:
        result = testimonials_collection.delete_one({"name": name})
        if result.deleted_count == 0:
            return jsonify({"error": "Testimonial not found"}), 404
        return jsonify({"message": "Testimonial deleted successfully"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/upload_testimonial")
def upload_testimonial_page():
    current_user = get_current_user()
    if not current_user or current_user.get("role") != "admin":
        return redirect("/admin_login")
    testimonials = list(testimonials_collection.find({}, {"_id": 0}))
    return render_template("upload_testimonial.html", current_user=current_user, testimonials=testimonials)

@app.route("/")
def home():
    testimonials = list(testimonials_collection.find({}, {"_id": 0}))
    return render_template("home.html", current_user=get_current_user(), testimonials=testimonials)

@app.route("/about")
def about():
    testimonials = list(testimonials_collection.find({}, {"_id": 0}))
    return render_template("about.html", current_user=get_current_user() , testimonials=testimonials)

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
        if not users_collection.find_one({"username": username}):
            return username

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

        df = pd.read_excel(file_path)  # Load Excel data
        df.columns = df.columns.str.lower()

        results = []
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = []
            for _, row in df.iterrows():
                if users_collection.find_one({"email": row["email"]}):
                    results.append(f"Email {row['email']} already exists.")
                    continue
                base_username = row["email"].split("@")[0]
                username = generate_unique_username(base_username)
                password = generate_random_password()
                hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
                user_data = {
                    "name": row["name"],
                    "email": row["email"],
                    "username": username,
                    "password": hashed_password,
                    "role": "user"
                }
                users_collection.insert_one(user_data)  # Save user data to the database
                futures.append(executor.submit(send_email, row["email"], username, password))
            for future in as_completed(futures):
                results.append(future.result())

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

        if users_collection.find_one({"email": email}):
            return jsonify({"error": "Email already exists"}), 400
            
        password = generate_random_password()
        username = generate_unique_username(base_username)
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        users_collection.insert_one({
            "name": name,
            "email": email,
            "username": username,
            "password": hashed_password,
            "role": "user"
        })
            
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
        demo_files = list(files_collection.find({"demo_type": True}, {"_id": 0, "filename": 1, "demo_type": 1}))
        return jsonify({"files": demo_files})
    except Exception as e:
        return jsonify({"error": str(e)}), 500



@app.route("/admin_testimonials")
def admin_testimonials():
            current_user = get_current_user()
            if not current_user or current_user.get("role") != "admin":
                return redirect("/admin_login")
            testimonials = list(testimonials_collection.find({}, {"_id": 0}))
            return render_template("upload_testimonial.html", current_user=current_user, testimonials=testimonials)

if __name__ == "__main__":
    app.run(debug=True)