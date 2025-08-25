<?php
require 'vendor/autoload.php'; // Composer autoload

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;
use PHPMailer\PHPMailer\OAuth;
use League\OAuth2\Client\Provider\Google; // Import the Google provider

const SMTP_SERVER = "smtp.gmail.com";
const SMTP_PORT = 587;
$sender_email = "rahul.11919011621@ipu.ac.in";

function get_access_token() {
    $url = "https://oauth2.googleapis.com/token";
    $data = [
        "client_id" => "demo",
        "client_secret" => "demo",
        "refresh_token" => "demo",
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

        $mail = new PHPMailer(true);
        $mail->isSMTP();
        $mail->Host = SMTP_SERVER;
        $mail->SMTPAuth = true;
        $mail->SMTPSecure = 'tls';
        $mail->Port = SMTP_PORT;
        $mail->AuthType = 'XOAUTH2';
        
        $mail->setOAuth(
            new OAuth([
                'provider' => new Google([
                    'clientId' => "696722818906-si3am383fsavh4irf5im892aak93tenc.apps.googleusercontent.com",
                    'clientSecret' => "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",
                ]),
                'clientId' => "696722818906-si3am383fsavh4irf5im892aak93tenc.apps.googleusercontent.com",
                'clientSecret' => "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",
                'refreshToken' => "1//04AMLLFsXNPkmCgYIARAAGAQSNwF-L9IrUiy9RmtHLINDIY5hXaxZQmlOGS5-PCEKphCq0ST2n9Jb1z7L2jPv8L2oXQItGgC6Al4",
                'userName' => $sender_email,
                'accessToken' => $access_token,
            ])
        );

        $mail->setFrom($sender_email);
        $mail->addAddress($to_email);
        $mail->Subject = $subject;
        $mail->isHTML(true);
        $mail->Body = $body;

        $mail->send();
        return "Email sent to {$to_email}";
    } catch (Exception $e) {
        return "Failed to send email to {$to_email}. Error: " . $e->getMessage();
    }
}
?>
