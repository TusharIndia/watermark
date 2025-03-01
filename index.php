<?php
// Prevent direct execution issues in CLI by defining a guard
if (!defined('APP_RUNNING')) {
    define('APP_RUNNING', true);
} else {
    exit; // Prevent multiple inclusions
}

require 'vendor/autoload.php';

use Dotenv\Dotenv;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use PhpOffice\PhpSpreadsheet\IOFactory;
use setasign\Fpdi\Fpdi;
use Twig\Environment;
use Twig\Loader\FilesystemLoader;

// Load environment variables
$dotenv = Dotenv::createImmutable(__DIR__);
$dotenv->load();
require_once 'email_stepup.php';
$secret_key = $_ENV['SECRET_KEY'];
$admin_username = $_ENV['ADMIN_NAME'];
$admin_password = $_ENV['ADMIN_PASS'];


define('UPLOAD_FOLDER', 'uploads');
define('WATERMARKED_FOLDER', 'watermarked_pdfs');

// Ensure directories exist
if (!file_exists(UPLOAD_FOLDER)) mkdir(UPLOAD_FOLDER, 0777, true);
if (!file_exists(WATERMARKED_FOLDER)) mkdir(WATERMARKED_FOLDER, 0777, true);

// MySQL connection
$db_config = [
    'host' => 'srv1824.hstgr.io',
    'user' => 'u145695899_UdaanByRobot',
    'password' => 'UdaanByRobot2025Upsc',
    'database' => 'u145695899_Udaan'
];

if (!function_exists('get_db_connection')) {
    function get_db_connection() {
        global $db_config;
        $conn = new mysqli($db_config['host'], $db_config['user'], $db_config['password'], $db_config['database']);
        if ($conn->connect_error) die("Connection failed: " . $conn->connect_error);
        return $conn;
    }
}

// Twig setup
$loader = new FilesystemLoader(__DIR__ . '/templates');
$twig = new Environment($loader);

// Helper to get current user from JWT cookie

if (!function_exists('user_get_auth')) {
    function user_get_auth() {
        global $secret_key;
        $token = isset($_COOKIE['token']) ? $_COOKIE['token'] : null;
        if (!$token) return false;

        try {
            return JWT::decode($token, new Key($secret_key, 'HS256'));
        } catch (Exception $e) {
            return null;
        }
    }
}


// Simulate HTTP request for CLI debugging
if (PHP_SAPI === 'cli') {
    $_SERVER['REQUEST_METHOD'] = 'GET';
    $_SERVER['REQUEST_URI'] = isset($argv[1]) ? $argv[1] : '/';
}

// Routing
$request_method = $_SERVER['REQUEST_METHOD'];
$request_uri = strtok($_SERVER['REQUEST_URI'], '?');

// Login (POST /logins)
if ($request_uri === '/logins' && $request_method === 'POST') {
    $data = json_decode(file_get_contents('php://input'), true);
    $username = $data['username'] ?? '';
    $password = $data['password'] ?? '';

    $conn = get_db_connection();
    $stmt = $conn->prepare("SELECT * FROM users WHERE username = ?");
    $stmt->bind_param("s", $username);
    $stmt->execute();
    $user = $stmt->get_result()->fetch_assoc();
    $conn->close();

    if ($user && password_verify($password, $user['password'])) {
        if (user_get_auth()) {
            header('Content-Type: application/json');
            echo json_encode(['error' => 'Already logged in']);
            http_response_code(400);
            exit;
        }
        if ($user['role'] === 'admin') {
            header('Content-Type: application/json');
            echo json_encode(['error' => 'Invalid credentials']);
            http_response_code(401);
            exit;
        }
        $token = JWT::encode(['username' => $user['username'], 'role' => $user['role'] ?? 'user'], $secret_key, 'HS256');
        $user_data = ['username' => $user['username'], 'role' => $user['role'] ?? 'user', 'name' => $user['name'], 'email' => $user['email']];
        header('Content-Type: application/json');
        setcookie('token', $token, 0, '/', '', false, true);
        echo json_encode(['message' => 'Login successful', 'data' => $user_data, 'role' => $user['role'], 'token' => $token]);
        exit;
    }
    header('Content-Type: application/json');
    echo json_encode(['error' => 'Invalid credentials']);
    http_response_code(401);
    exit;
}

// Admin Login (POST /adm-login)
if ($request_uri === '/adm-login' && $request_method === 'POST') {
    $data = json_decode(file_get_contents('php://input'), true);
    $username = $data['username'] ?? '';
    $password = $data['password'] ?? '';
    
    if ($username === $admin_username && $password === $admin_password ) {
        if (user_get_auth()) {
            header('Content-Type: application/json');
            echo json_encode(['error' => 'Already logged in']);
            http_response_code(400);
            exit;
        }
        $token = JWT::encode(['username' => $admin_username, 'role' => 'admin'], $secret_key, 'HS256');
        $user_data = ['username' => $admin_username, 'role' => 'admin'];
        header('Content-Type: application/json');
        setcookie('token', $token, 0, '/', '', false, true);
        echo json_encode(['message' => 'Login successful', 'data' => $user_data, 'role' => 'admin', 'token' => $token]);
        exit;
    }
    header('Content-Type: application/json');
    echo json_encode(['error' => 'Invalid credentials']);
    http_response_code(401);
    exit;
}

// Upload PDF (POST /upload)
// if ($request_uri === '/upload' && $request_method === 'POST') {
//     $current_user = user_get_auth();
//     if (!$current_user || $current_user->role !== 'admin') {
//         header('Content-Type: application/json');
//         echo json_encode(['error' => 'Only admin can upload files']);
//         http_response_code(403);
//         exit;
//     }
//     if (!isset($_FILES['file'])) {
//         header('Content-Type: application/json');
//         echo json_encode(['error' => 'No file part']);
//         http_response_code(400);
//         exit;
//     }
//     $file = $_FILES['file'];
//     if ($file['name'] === '') {
//         header('Content-Type: application/json');
//         echo json_encode(['error' => 'No selected file']);
//         http_response_code(400);
//         exit;
//     }
//     $filename = basename($file['name']);
//     $file_path = UPLOAD_FOLDER . '/' . $filename;

//     if (file_exists($file_path)) {
//         $new_hash = md5_file($file['tmp_name']);
//         $existing_hash = md5_file($file_path);
//         if ($new_hash === $existing_hash) {
//             header('Content-Type: application/json');
//             echo json_encode(['error' => 'File already uploaded']);
//             http_response_code(400);
//             exit;
//         }
//     }

//     move_uploaded_file($file['tmp_name'], $file_path);

//     $conn = get_db_connection();
//     $stmt = $conn->prepare("INSERT INTO files (filename, uploaded_by, demo_type) VALUES (?, ?, ?)");
//     $uploaded_by = $admin_username;
//     $demo_type = 0;
//     $stmt->bind_param("ssi", $filename, $uploaded_by, $demo_type);
//     $stmt->execute();
//     $conn->close();

//     header('Content-Type: application/json');
//     echo json_encode(['message' => 'File uploaded successfully', 'filename' => $filename]);
//     exit;
// }

// Upload PDF (POST /upload)
if ($request_uri === '/upload' && $request_method === 'POST') {
    $current_user = user_get_auth();
    if (!$current_user || $current_user->role !== 'admin') {
        header('Content-Type: application/json');
        echo json_encode(['error' => 'Only admin can upload files']);
        http_response_code(403);
        exit;
    }

    if (!isset($_FILES['file'])) {
        header('Content-Type: application/json');
        echo json_encode(['error' => 'No file part']);
        http_response_code(400);
        exit;
    }

    $file = $_FILES['file'];
    if (empty($file['name'])) { // Match Python's check for empty filename
        header('Content-Type: application/json');
        echo json_encode(['error' => 'No selected file']);
        http_response_code(400);
        exit;
    }

    // Use secure_filename equivalent (basename is already safe, but we can add sanitization)
    $filename = basename($file['name']); // Matches Python's secure_filename
    $file_path = UPLOAD_FOLDER . '/' . $filename;

    // Check if file exists and compare MD5 hashes (matching Python's hashlib.md5)
    if (file_exists($file_path)) {
        // Read the uploaded file content
        $new_contents = file_get_contents($file['tmp_name']);
        $new_hash = md5($new_contents); // Use md5() to match Python's hashlib.md5

        // Read the existing file content
        $existing_contents = file_get_contents($file_path);
        $existing_hash = md5($existing_contents);

        if ($new_hash === $existing_hash) {
            header('Content-Type: application/json');
            echo json_encode(['error' => 'File already uploaded']);
            http_response_code(400);
            exit;
        }
    }

    // Save the file (matches Python's file.save())
    if (!move_uploaded_file($file['tmp_name'], $file_path)) {
        header('Content-Type: application/json');
        echo json_encode(['error' => 'Failed to save file']);
        http_response_code(500);
        exit;
    }

    // Define $demo_type at the start of the route to avoid "Undefined variable" warning
    $demo_type = 0; // Matches Python's False

    // Database insertion (matching Python's SQL query)
    try {
        $conn = get_db_connection();
        if (!$conn) {
            throw new Exception("Database connection failed");
        }

        // Debug: Log the values being inserted
        error_log("Inserting into files: filename=$filename, uploaded_by=$admin_username, demo_type=$demo_type");

        $stmt = $conn->prepare("INSERT INTO files (filename, uploaded_by, demo_type) VALUES (?, ?, ?)");
        if (!$stmt) {
            throw new Exception("Prepare failed: " . $conn->error);
        }

        $uploaded_by = $admin_username; // Ensure this is loaded from .env or defined

        // Debug: Check variable types and values
        error_log("Filename type: " . gettype($filename) . ", value: " . $filename);
        error_log("Uploaded_by type: " . gettype($uploaded_by) . ", value: " . $uploaded_by);
        error_log("Demo_type type: " . gettype($demo_type) . ", value: " . $demo_type);

        $stmt->bind_param("ssi", $filename, $uploaded_by, $demo_type);
        if (!$stmt->execute()) {
            throw new Exception("Execute failed: " . $stmt->error);
        }

        $conn->close();

        // Return JSON response (matching Python's jsonify)
        header('Content-Type: application/json');
        echo json_encode(['message' => 'File uploaded successfully', 'filename' => $filename]);
        exit;
    } catch (Exception $e) {
        // Clean up if connection exists
        if (isset($conn) && $conn) {
            $conn->close();
        }
        if (isset($stmt)) {
            $stmt->close();
        }

        header('Content-Type: application/json');
        echo json_encode(['error' => 'Database error: ' . $e->getMessage()]);
        http_response_code(500);
        exit;
    }
}


// List Files (GET /files)
if ($request_uri === '/files' && $request_method === 'GET') {
    if (!user_get_auth()) {
        header('Content-Type: application/json');
        echo json_encode(['error' => 'Unauthorized']);
        http_response_code(403);
        exit;
    }
    $conn = get_db_connection();
    $result = $conn->query("SELECT filename, demo_type FROM files");
    $files = [];
    while ($row = $result->fetch_assoc()) $files[] = $row;
    $conn->close();
    header('Content-Type: application/json');
    echo json_encode(['files' => $files]);
    exit;
}

// Watermark PDF Function
if (!function_exists('add_watermark')) {
    function add_watermark($input_pdf_path, $output_pdf_path, $username) {
        $pdf = new Fpdi();
        $page_count = $pdf->setSourceFile($input_pdf_path);

        $temp_pdf_path = $output_pdf_path . '_temp.pdf';
        for ($page_no = 1; $page_no <= $page_count; $page_no++) {
            $tpl_id = $pdf->importPage($page_no);
            $pdf->AddPage();
            $pdf->useTemplate($tpl_id);
            $pdf->SetFont('Helvetica', '', 50);
            $pdf->SetTextColor(180, 180, 180);
            $pdf->SetXY(100, 100);
            $pdf->Write(0, $username);
        }
        $pdf->Output('F', $temp_pdf_path);

        // Convert to images and back to PDF (similar to Python's logic)
        $imagick = new Imagick();
        $imagick->readImage($temp_pdf_path);
        $images = [];
        $temp_dir = 'temp_images';
        if (!file_exists($temp_dir)) mkdir($temp_dir, 0777, true);

        foreach ($imagick as $i => $page) {
            $img_path = "$temp_dir/page_$i.png";
            $page->setImageFormat('png');
            $page->writeImage($img_path);
            $images[] = $img_path;
        }

        $imagick->clear();
        $imagick->destroy();

        $final_pdf = new Fpdi();
        foreach ($images as $img) {
            $final_pdf->AddPage();
            $final_pdf->Image($img, 0, 0, $final_pdf->GetPageWidth(), $final_pdf->GetPageHeight());
        }
        $final_pdf->Output('F', $output_pdf_path);

        unlink($temp_pdf_path);
        foreach ($images as $img) unlink($img);
        rmdir($temp_dir);
    }
}

// Download PDF (GET /download/<filename>)
if (preg_match('#^/download/(.+)$#', $request_uri, $matches) && $request_method === 'GET') {
    $filename = $matches[1];
    $current_user = user_get_auth();
    if (!$current_user || $current_user->role !== 'user') {
        header('Content-Type: application/json');
        echo json_encode(['error' => 'Unauthorized']);
        http_response_code(403);
        exit;
    }
    $input_pdf_path = UPLOAD_FOLDER . '/' . $filename;
    if (!file_exists($input_pdf_path)) {
        header('Content-Type: application/json');
        echo json_encode(['error' => 'File not found']);
        http_response_code(404);
        exit;
    }
    $output_pdf_path = WATERMARKED_FOLDER . '/' . $current_user->username . '_' . $filename;
    add_watermark($input_pdf_path, $output_pdf_path, $current_user->username);

    header('Content-Type: application/pdf');
    header('Content-Disposition: attachment; filename="' . basename($output_pdf_path) . '"');
    readfile($output_pdf_path);

    // Delete file after 20 seconds
    sleep(20);
    unlink($output_pdf_path);
    exit;
}

// Get Uploaded File (GET /uploads/<filename>)
if (preg_match('#^/uploads/(.+)$#', $request_uri, $matches) && $request_method === 'GET') {
    $filename = $matches[1];
    $file_path = UPLOAD_FOLDER . '/' . $filename;
    if (!file_exists($file_path)) {
        header('Content-Type: application/json');
        echo json_encode(['error' => 'File not found']);
        http_response_code(404);
        exit;
    }
    header('Content-Type: application/octet-stream');
    readfile($file_path);
    exit;
}


if ($request_uri === "/delete" && $request_method === "POST") {
    $input = json_decode(file_get_contents("php://input"), true);
    if (empty($input['filename'])) {
        exit(json_encode(['error' => 'Filename is required']));
    }

    $current_user = user_get_auth();
    if ($current_user->role !== 'admin') {
        exit(json_encode(['error' => 'Unauthorized']));
    }

    $conn = get_db_connection();
    $stmt = $conn->prepare("DELETE FROM files WHERE filename = ?");
    $stmt->bind_param("s", $input['filename']);
    $stmt->execute();

    if ($stmt->affected_rows > 0) {
        $file_path = UPLOAD_FOLDER . '/' . $input['filename'];
        if (file_exists($file_path)) {
            unlink($file_path);
        }
        exit(json_encode(['message' => 'File deleted successfully']));
    }

    exit(json_encode(['error' => 'File record not found']));
}


// Set Demo Type (POST /set_demo/<filename>)
if ($request_uri === "/set_demo" && $request_method === "POST") {
    $input = json_decode(file_get_contents("php://input"), true);

    if (!isset($input['filename'])) {
        header('Content-Type: application/json');
        echo json_encode(['error' => 'Filename is required']);
        http_response_code(400);
        exit;
    }

    $filename = $input['filename'];
    $current_user = user_get_auth();

    if (!$current_user || $current_user->role !== 'admin') {
        header('Content-Type: application/json');
        echo json_encode(['error' => 'Only admin can change demo type status']);
        http_response_code(403);
        exit;
    }

    $conn = get_db_connection();
    $stmt = $conn->prepare("SELECT demo_type FROM files WHERE filename = ?");
    $stmt->bind_param("s", $filename);
    $stmt->execute();
    $file = $stmt->get_result()->fetch_assoc();

    if (!$file) {
        $conn->close();
        header('Content-Type: application/json');
        echo json_encode(['error' => 'File not found']);
        http_response_code(404);
        exit;
    }

    $new_demo_type = !$file['demo_type'];
    $stmt = $conn->prepare("UPDATE files SET demo_type = ? WHERE filename = ?");
    $stmt->bind_param("is", $new_demo_type, $filename);
    $stmt->execute();
    $conn->close();

    header('Content-Type: application/json');
    echo json_encode(['demo_type' => $new_demo_type, 'message' => "Demo type status set to $new_demo_type for $filename"]);
    exit;
}

// Logout (POST /logout)
if ($request_uri === '/logout' && $request_method === 'POST') {
    header('Content-Type: application/json');
    setcookie('token', '', time() - 3600, '/', '', false, true);
    echo json_encode(['message' => 'Logged out successfully']);
    exit;
}

// Testimonials Routes
if ($request_uri === '/api/testimonials' && $request_method === 'POST') {
    try {
        $data = $_POST;
        $name = $data['name'] ?? null;
        $description = $data['description'] ?? null;
        $image_url = $data['image_url'] ?? null;

        if (!$name || !$description || !$image_url) {
            header('Content-Type: application/json');
            echo json_encode(['error' => 'All fields are required']);
            http_response_code(400);
            exit;
        }

        // Generate a unique key
        $testimonials_id = uniqid('test_', true); // Generates something like "test_65dfca3f1a4a1.12345678"

        $conn = get_db_connection();
        $stmt = $conn->prepare("INSERT INTO testimonials (testimonials_id, name, image, description) VALUES (?, ?, ?, ?)");
        $stmt->bind_param("ssss", $testimonials_id, $name, $image_url, $description);
        $stmt->execute();
        $conn->close();

        header('Content-Type: application/json');
        echo json_encode([
            'message' => 'Testimonial added successfully',
            'unique_key' => $testimonials_id
        ]);
        exit;
    } catch (Exception $e) {
        header('Content-Type: application/json');
        echo json_encode(['error' => $e->getMessage()]);
        http_response_code(500);
        exit;
    }
}



if ($request_uri === '/api/testimonials/delete' && $request_method === 'POST') {
    // Get JSON body data
    $input = json_decode(file_get_contents("php://input"), true);

    if (!isset($input['id'])) {
        header('Content-Type: application/json');
        echo json_encode(['error' => 'Testimonial ID is required']);
        http_response_code(400);
        exit;
    }

    $id = $input['id'];

    // Database connection
    $conn = get_db_connection();
    $stmt = $conn->prepare("DELETE FROM testimonials WHERE  name= ?");
    $stmt->bind_param("s", $id);
    $stmt->execute();

    if ($stmt->affected_rows == 0) {
        $conn->close();
        header('Content-Type: application/json');
        echo json_encode(['error' => 'Testimonial not found']);
        http_response_code(404);
        exit;
    }

    $conn->close();
    header('Content-Type: application/json');
    echo json_encode(['message' => 'Testimonial deleted successfully']);
    exit;
}




// Page Routes
if ($request_uri === '/upload_testimonial' && $request_method === 'GET') {
    $current_user = user_get_auth();
    if (!$current_user || $current_user->role !== 'admin') {
        header('Location: /admin_login');
        exit;
    }
    $conn = get_db_connection();
    $result = $conn->query("SELECT * FROM testimonials");
    $testimonials = [];
    while ($row = $result->fetch_assoc()) $testimonials[] = $row;
    $conn->close();
    echo $twig->render('upload_testimonial.html', ['current_user' => $current_user, 'testimonials' => $testimonials]);
    exit;
}

if ($request_uri === '/' && $request_method === 'GET') {
    $conn = get_db_connection();
    $result = $conn->query("SELECT name, image, description FROM testimonials");
    $testimonials = [];
    while ($row = $result->fetch_assoc()) {
        $testimonials[] = $row;
    }
    $conn->close();

    // Explicitly fetch current_user
    $current_user = user_get_auth();

    // Debug: Log the current_user to verify it's being retrieved
    error_log('Current User: ' . print_r($current_user, true));

    // Render the template with current_user and testimonials
    echo $twig->render('home.html', [
        'current_user' => $current_user,
        'testimonials' => $testimonials
    ]);
    exit;
}

if ($request_uri === '/about' && $request_method === 'GET') {
    $conn = get_db_connection();
    $result = $conn->query("SELECT name, image, description FROM testimonials");
    $testimonials = [];
    while ($row = $result->fetch_assoc()) $testimonials[] = $row;
    $conn->close();
    echo $twig->render('about.html', ['current_user' => user_get_auth(), 'testimonials' => $testimonials]);
    exit;
}

if ($request_uri === '/login' && $request_method === 'GET') {
    $current_user = user_get_auth();
    if ($current_user) {
        header('Location: ' . ($current_user->role === 'user' ? '/user_files' : '/admin'));
        exit;
    }
    echo $twig->render('login.html', ['current_user' => null]);
    exit;
}

if ($request_uri === '/admin_login' && $request_method === 'GET') {
    $current_user = user_get_auth();
    if ($current_user) {
        header('Location: ' . ($current_user->role === 'user' ? '/user_files' : '/admin'));
        exit;
    }
    echo $twig->render('admin_login.html', ['current_user' => null]);
    exit;
}

if ($request_uri === '/admin' && $request_method === 'GET') {
    $current_user = user_get_auth();
    if (!$current_user || $current_user->role !== 'admin') {
        header('Location: /admin_login');
        exit;
    }
    echo $twig->render('admin.html', ['current_user' => $current_user]);
    exit;
}

if ($request_uri === '/user_files' && $request_method === 'GET') {
    $current_user = user_get_auth();
    if (!$current_user || $current_user->role !== 'user') {
        header('Location: /logins');
        exit;
    }
    echo $twig->render('user_files.html', ['current_user' => $current_user]);
    exit;
}

if ($request_uri === '/admin_create_user' && $request_method === 'GET') {
    $current_user = user_get_auth();
    if (!$current_user || $current_user->role !== 'admin') {
        header('Location: /admin_login');
        exit;
    }
    echo $twig->render('admin_create_user.html', ['current_user' => $current_user]);
    exit;
}

if ($request_uri === '/admin_upload' && $request_method === 'GET') {
    $current_user = user_get_auth();
    if (!$current_user || $current_user->role !== 'admin') {
        header('Location: /admin_login');
        exit;
    }
    echo $twig->render('admin_upload_file.html', ['current_user' => $current_user]);
    exit;
}

// Utility Functions
if (!function_exists('generate_unique_username')) {
    function generate_unique_username($base_username) {
        while (true) {
            $username = "udaan_{$base_username}_" . rand(1000, 9999);
            $conn = get_db_connection();
            $stmt = $conn->prepare("SELECT COUNT(*) FROM users WHERE username = ?");
            $stmt->bind_param("s", $username);
            $stmt->execute();
            $count = $stmt->get_result()->fetch_row()[0];
            $conn->close();
            if ($count == 0) return $username;
        }
    }
}

if (!function_exists('generate_random_password')) {
    function generate_random_password($length = 8) {
        $characters = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()';
        return substr(str_shuffle($characters), 0, $length);
    }
}

if (!function_exists('send_email')) {
    function send_email($email, $username, $password) {
        // Implement email sending logic here (e.g., using PHPMailer)
        // For simplicity, this is a placeholder
        return "Email sent to $email with username: $username, password: $password";
    }
}

// Send Bulk Emails (POST /send-emails)
if ($request_uri === '/send-emails' && $request_method === 'POST') {
    try {
        $current_user = user_get_auth();
        if (!$current_user || $current_user->role !== 'admin') {
            header('Content-Type: application/json');
            echo json_encode(['error' => 'Only admin can upload Excel files']);
            http_response_code(403);
            exit;
        }

        if (!isset($_FILES['excel_file'])) {
            header('Content-Type: application/json');
            echo json_encode(['error' => 'No file part']);
            http_response_code(400);
            exit;
        }

        $excel_file = $_FILES['excel_file'];
        if ($excel_file['name'] === '') {
            header('Content-Type: application/json');
            echo json_encode(['error' => 'No selected file']);
            http_response_code(400);
            exit;
        }

        $filename = basename($excel_file['name']);
        $file_path = UPLOAD_FOLDER . '/' . $filename;
        
        if (!move_uploaded_file($excel_file['tmp_name'], $file_path)) {
            throw new Exception("Failed to move uploaded file");
        }

        $spreadsheet = IOFactory::load($file_path);
        $sheet = $spreadsheet->getActiveSheet();
        $data = $sheet->toArray(null, true, true, true);

        $results = [];
        $conn = get_db_connection();
        
        foreach ($data as $row) {
            $email = strtolower($row['B'] ?? '');
            $name = $row['A'] ?? '';
            if (!$email || !$name) continue;

            // Validate email format
            if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
                $results[] = "Invalid email address: $email";
                continue;
            }

            $stmt = $conn->prepare("SELECT COUNT(*) FROM users WHERE email = ?");
            $stmt->bind_param("s", $email);
            $stmt->execute();
            if ($stmt->get_result()->fetch_row()[0] > 0) {
                $results[] = "Email $email already exists.";
                continue;
            }

            $base_username = explode('@', $email)[0];
            $username = generate_unique_username($base_username);
            $password = generate_random_password();
            $hashed_password = password_hash($password, PASSWORD_BCRYPT);
            $role = 'user';

            $stmt = $conn->prepare("INSERT INTO users (name, email, username, password, role) VALUES (?, ?, ?, ?, ?)");
            $stmt->bind_param("sssss", $name, $email, $username, $hashed_password, $role);
            $stmt->execute();
            
            // Debug log
            $results[] = "Debug: Sending to Email: $email, Username: $username";
            $results[] = send_email($email, $username, $password);
        }

        $conn->close();
        unlink($file_path);

        header('Content-Type: application/json');
        echo json_encode(['message' => 'Emails sent successfully!', 'details' => $results]);
        exit;
    } catch (Exception $e) {
        if (file_exists($file_path)) {
            unlink($file_path);
        }
        header('Content-Type: application/json');
        echo json_encode(['error' => $e->getMessage()]);
        http_response_code(500);
        exit;
    }
}

// Create User (POST /create_user)
if ($request_uri === '/create_user' && $request_method === 'POST') {
    $current_user = user_get_auth();
    if (!$current_user || $current_user->role !== 'admin') {
        header('Content-Type: application/json');
        echo json_encode(['error' => 'Only admin can create users']);
        http_response_code(403);
        exit;
    }
    $data = json_decode(file_get_contents('php://input'), true);
    $name = $data['name'] ?? '';
    $email = $data['email'] ?? '';
    if (!$name || !$email) {
        header('Content-Type: application/json');
        echo json_encode(['error' => 'All fields are required']);
        http_response_code(400);
        exit;
    }
    $conn = get_db_connection();
    $stmt = $conn->prepare("SELECT COUNT(*) FROM users WHERE email = ?");
    $stmt->bind_param("s", $email);
    $stmt->execute();
    if ($stmt->get_result()->fetch_row()[0] > 0) {
        $conn->close();
        header('Content-Type: application/json');
        echo json_encode(['error' => 'Email already exists']);
        http_response_code(400);
        exit;
    }
    $base_username = explode('@', $email)[0];
    $username = generate_unique_username($base_username);
    $password = generate_random_password();
    $hashed_password = password_hash($password, PASSWORD_BCRYPT);
    $role = 'user';
    $stmt = $conn->prepare("INSERT INTO users (name, email, username, password, role) VALUES (?, ?, ?, ?, ?)");
    $stmt->bind_param("sssss", $name, $email, $username, $hashed_password, $role);
    $stmt->execute();
    $conn->close();

    send_email($email, $username, $password);
    header('Content-Type: application/json');
    echo json_encode(['message' => 'User created successfully and email sent!']);
    exit;
}

// Test Series (GET /test-series)
if ($request_uri === '/test-series' && $request_method === 'GET') {
    $current_user = user_get_auth();
    echo $twig->render('test_series.html', ['current_user' => $current_user]);
    exit;
}

// Demo Files (GET /demo-files)
if ($request_uri === '/demo-files' && $request_method === 'GET') {
    $conn = get_db_connection();
    $result = $conn->query("SELECT filename, demo_type FROM files WHERE demo_type = TRUE");
    $files = [];
    while ($row = $result->fetch_assoc()) $files[] = $row;
    $conn->close();
    header('Content-Type: application/json');
    echo json_encode(['files' => $files]);
    exit;
}

// Admin Testimonials (GET /admin_testimonials)
if ($request_uri === '/admin_testimonials' && $request_method === 'GET') {
    $current_user = user_get_auth();
    if (!$current_user || $current_user->role !== 'admin') {
        header('Location: /admin_login');
        exit;
    }
    $conn = get_db_connection();
    $result = $conn->query("SELECT name, image, description FROM testimonials");
    $testimonials = [];
    while ($row = $result->fetch_assoc()) $testimonials[] = $row;
    $conn->close();
    echo $twig->render('upload_testimonial.html', ['current_user' => $current_user, 'testimonials' => $testimonials]);
    exit;
}

// Default 404
header('Content-Type: application/json');
echo json_encode(['error' => 'Not Found']);
http_response_code(404);
?>