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
use setasign\Fpdi\Tcpdf\Fpdi as TcpdfFpdi;
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




function delete_file_later($file_path, $delay = 10) {
    // Use a background process to delete the file after delay
    if (PHP_OS_FAMILY === 'Windows') {
        // Windows command
        $cmd = "ping 127.0.0.1 -n " . ($delay + 1) . " > nul && del " . escapeshellarg($file_path);
        exec($cmd . " > nul 2>&1 &");
    } else {
        // Unix-like systems (Linux, macOS)
        $cmd = "sleep " . $delay . " && rm -f " . escapeshellarg($file_path);
        exec($cmd . " > /dev/null 2>&1 &");
    }
}

function convertPdfToImagesAndBack($inputPath, $outputPath) {
    try {
        // Validate file is a PDF
        if (mime_content_type($inputPath) !== 'application/pdf') {
            return [
                'success' => false,
                'message' => 'Please provide a valid PDF file.'
            ];
        }

        // Step 1: Convert PDF pages to images
        $imagick = new Imagick();
        $imagick->setResolution(150, 150); // Set resolution for quality
        $imagick->readImage($inputPath); // Read all pages of the PDF

        $pageCount = $imagick->getNumberImages();
        $imageFiles = [];
        $tempDir = dirname($outputPath) . '/temp_' . uniqid() . '/';

        // Create temporary directory if it doesn't exist
        if (!file_exists($tempDir)) {
            mkdir($tempDir, 0777, true);
        }

        for ($i = 0; $i < $pageCount; $i++) {
            $imagick->setIteratorIndex($i); // Set to specific page
            $imagick->setImageFormat('png'); // Convert to PNG
            $imagePath = $tempDir . "page_$i.png";
            $imagick->writeImage($imagePath); // Save image
            $imageFiles[] = $imagePath;
        }

        // Step 2: Combine images back into a PDF
        $combined = new Imagick($imageFiles);
        $combined->setImageFormat('pdf');
        $combined->writeImages($outputPath, true); // True to combine into one file

        // Clean up temporary image files and directory
        foreach ($imageFiles as $file) {
            unlink($file);
        }
        rmdir($tempDir);

        return $output_path;

    } catch (Exception $e) {
        // Clean up in case of error
        if (isset($imageFiles) && !empty($imageFiles)) {
            foreach ($imageFiles as $file) {
                if (file_exists($file)) {
                    unlink($file);
                }
            }
        }
        if (isset($tempDir) && file_exists($tempDir)) {
            rmdir($tempDir);
        }

        return [
            'success' => false,
            'message' => 'Error processing PDF: ' . $e->getMessage()
        ];
    }
}

function createWatermarkedPdf($filename, $current_user, $output_path) {
    // Create new PDF instance using FPDI for TCPDF
    $pdf = new TcpdfFpdi();

    // Remove default header/footer
    $pdf->setPrintHeader(false);
    $pdf->setPrintFooter(false);

    // Set document info
    $pdf->SetCreator('Grok 3');
    $pdf->SetAuthor('xAI');
    $pdf->SetTitle('Watermarked PDF');
    $pdf->SetSubject('Watermarked Document');

    // Use current directory as base
    $baseDir = __DIR__; // Current directory of this script
    
    // Construct full input path using the defined constant
    $inputFile = $baseDir . DIRECTORY_SEPARATOR . UPLOAD_FOLDER . DIRECTORY_SEPARATOR . $filename;
    $outputFile = $output_path; // Use provided output path directly

    // Load source PDF
    $pageCount = $pdf->setSourceFile($inputFile);

    // Loop through all pages
    for ($i = 1; $i <= $pageCount; $i++) {
        $pdf->AddPage();
        $tplIdx = $pdf->importPage($i);
        $pdf->useTemplate($tplIdx);

        // Set watermark properties
        $pdf->SetFont('Helvetica', 'B', 40);
        $pdf->SetTextColor(200, 200, 200); // Lighter gray
        $pdf->SetAlpha(0.2); // Set transparency

        // Apply rotated watermark (using username as watermark)
        $pdf->StartTransform();
        $pdf->Rotate(45, 55, 175);
        $pdf->Text(55, 175, $current_user);
        $pdf->StopTransform();

        // Reset alpha
        $pdf->SetAlpha(1);
    }

    // Save the output file
    $pdf->Output($outputFile, 'F');
    $newfileOutput = convertPdfToImagesAndBack($outputFile, $outputFile);
    
    // Return output file path
    return $newfileOutput;
}

if ($request_uri === '/download' && $request_method === 'POST') {
    
    $raw_data = file_get_contents('php://input');
    $data = json_decode($raw_data, true);
    
    if (!isset($data['filename']) || empty($data['filename'])) {
        header('Content-Type: application/json');
        http_response_code(400);
        echo json_encode(['error' => 'Filename is required in request body']);
        exit;
    }

    $current_user = user_get_auth();
    
    if (!$current_user || $current_user->role !== 'user') {
        header('Content-Type: application/json');
        http_response_code(403);
        echo json_encode(['error' => 'Unauthorized']);
        exit;
    }

    $filename = $data['filename'];
    
    // Use current directory as base
    $baseDir = __DIR__;
    $input_pdf_path = $baseDir . DIRECTORY_SEPARATOR . UPLOAD_FOLDER . DIRECTORY_SEPARATOR . $filename;
    $output_pdf_path = $baseDir . DIRECTORY_SEPARATOR . WATERMARKED_FOLDER . DIRECTORY_SEPARATOR . $current_user->username . '_' . $filename;

    // Check if input file exists
    if (!file_exists($input_pdf_path)) {
        header('Content-Type: application/json');
        http_response_code(404);
        echo json_encode(['error' => 'File not found at ' . $input_pdf_path]);
        exit;
    }

    // Create watermarked PDF
    $newfile =createWatermarkedPdf($filename, $current_user->username, $output_pdf_path);

    delete_file_later($output_pdf_path, 10);

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
if ($request_uri === '/send-emails' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    try {
        // Check if user is authenticated and has admin role
        $current_user = user_get_auth();
        if (!$current_user || $current_user->role !== 'admin') {
            header('Content-Type: application/json');
            echo json_encode(['error' => 'Only admin can upload Excel files']);
            http_response_code(403);
            exit;
        }

        // Check if file is uploaded
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

        // Sanitize and move the uploaded file
        $filename = basename($excel_file['name']);
        $file_path = UPLOAD_FOLDER . '/' . $filename;

        if (!move_uploaded_file($excel_file['tmp_name'], $file_path)) {
            throw new Exception("Failed to move uploaded file");
        }

        // Load and read the Excel file
        $spreadsheet = IOFactory::load($file_path);
        $sheet = $spreadsheet->getActiveSheet();
        $data = $sheet->toArray(null, true, true, true);

        $results = [];
        $conn = get_db_connection();

        // Process each row in the Excel sheet
        foreach ($data as $row) {
            // Based on your Excel sheet, columns are:
            // A: Email, B: Username, C: Password, D: name
            $email = strtolower($row['A'] ?? ''); // Email is in column A
            $name = $row['D'] ?? ''; // Name is in column D

            // Skip if email or name is empty
            if (!$email || !$name) continue;

            // Validate email format
            if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
                // echo "Invalid email address: $email";
                $results[] = "Invalid email address: $email";
                continue;
            }

            // Check if email already exists in the database
            $stmt = $conn->prepare("SELECT COUNT(*) FROM users WHERE email = ?");
            $stmt->bind_param("s", $email);
            $stmt->execute();
            if ($stmt->get_result()->fetch_row()[0] > 0) {
                $results[] = "Email $email already exists.";
                continue;
            }

            // Generate unique username and password
            $base_username = explode('@', $email)[0];
            $username = generate_unique_username($base_username);
            $password = generate_random_password();
            $hashed_password = password_hash($password, PASSWORD_BCRYPT);
            $role = 'user';

            // Insert user into the database
            $stmt = $conn->prepare("INSERT INTO users (name, email, username, password, role) VALUES (?, ?, ?, ?, ?)");
            $stmt->bind_param("sssss", $name, $email, $username, $hashed_password, $role);
            $stmt->execute();

            // Log debug information and send email
            $results[] = "Debug: Sending to Email: $email, Username: $username";
            $results[] = send_email($email, $username, $password);
        }

        // Close database connection and clean up
        $conn->close();
        unlink($file_path);

        // Return success response
        header('Content-Type: application/json');
        echo json_encode(['message' => 'Emails sent successfully!', 'details' => $results]);
        exit;
    } catch (Exception $e) {
        // Clean up if file exists and handle error
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