<?php
// email.php

// Gmail SMTP Configuration

const SMTP_SERVER = "smtp.gmail.com";
const SMTP_PORT = 587;
$sender_email = $_ENV['SENDER_EMAIL'];

function get_access_token() {
    $url = "https://oauth2.googleapis.com/token";
    $data = [
        "client_id" => $_ENV["CLIENT_ID"],
        "client_secret" => $_ENV["CLIENT_SECRET"],
        "refresh_token" => $_ENV["REFRESH_TOKEN"],
        "grant_type" => "refresh_token"
    ];

    $options = [
        'http' => [
            'header' => "Content-Type: application/x-www-form-urlencoded\r\n",
            'method' => 'POST',
            'content' => http_build_query($data),
        ],
    ];
    
    $context = stream_context_create($options);
    $response = file_get_contents($url, false, $context);
    
    if ($response === false) {
        throw new Exception("Failed to get access token");
    }
    
    $json_response = json_decode($response, true);
    if (isset($json_response['access_token'])) {
        return $json_response['access_token'];
    } else {
        throw new Exception("Failed to get access token: " . $response);
    }
}

function load_email_template($username, $password) {
    $template = file_get_contents("./templates/email_template.html");
    if ($template === false) {
        throw new Exception("Failed to load email template");
    }
    
    $template = str_replace("{username}", strval($username), $template);
    $template = str_replace("{password}", strval($password), $template);
    
    return $template;
}

function send_email($to_email, $username, $password) {
    global $sender_email;
    
    try {
        $access_token = get_access_token();
        $subject = "Welcome to Udaan UPSC – Your Login Credentials";
        $body = load_email_template($username, $password);

        $boundary = md5(uniqid());
        $headers = "From: " . $sender_email . "\r\n" .
                  "MIME-Version: 1.0\r\n" .
                  "Content-Type: multipart/alternative; boundary=\"{$boundary}\"\r\n";

        $message = "--{$boundary}\r\n" .
                  "Content-Type: text/html; charset=UTF-8\r\n" .
                  "Content-Transfer-Encoding: 7bit\r\n\r\n" .
                  $body . "\r\n" .
                  "--{$boundary}--";

        $smtp = fsockopen("tls://" . SMTP_SERVER, SMTP_PORT, $errno, $errstr, 30);
        if (!$smtp) {
            throw new Exception("Connection failed: $errstr ($errno)");
        }

        fgets($smtp, 515);
        fputs($smtp, "EHLO " . SMTP_SERVER . "\r\n");
        fgets($smtp, 515);
        fputs($smtp, "AUTH XOAUTH2 " . base64_encode("user={$sender_email}\1auth=Bearer {$access_token}\1\1") . "\r\n");
        $auth_response = fgets($smtp, 515);
        
        if (strpos($auth_response, "235") !== 0) {
            throw new Exception("Authentication failed: " . $auth_response);
        }

        fputs($smtp, "MAIL FROM:<{$sender_email}>\r\n");
        fgets($smtp, 515);
        fputs($smtp, "RCPT TO:<{$to_email}>\r\n");
        fgets($smtp, 515);
        fputs($smtp, "DATA\r\n");
        fgets($smtp, 515);
        fputs($smtp, "Subject: {$subject}\r\n{$headers}\r\n{$message}\r\n.\r\n");
        fgets($smtp, 515);
        fputs($smtp, "QUIT\r\n");
        fclose($smtp);

        return "Email sent to {$to_email}";

    } catch (Exception $e) {
        return "Failed to send email to {$to_email}. Error: " . $e->getMessage();
    }
}
?>