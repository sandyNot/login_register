<?php
session_start();

if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

require_once "./config.php";

$username_err = $email_err = $password_err = "";
$username = $email = $password = "";

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    if (isset($_POST['csrf_token']) && hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        if (empty(trim($_POST["username"]))) {
            $username_err = "Please enter a username.";
        } else {
            $username = trim($_POST["username"]);
            if (!ctype_alnum(str_replace(array("@", "-", "_"), "", $username))) {
                $username_err = "Username can only contain letters, numbers, and symbols like '@', '_', or '-'.";
            } else {
                $sql = "SELECT id FROM users WHERE username = ?";
                if ($stmt = mysqli_prepare($link, $sql)) {
                    mysqli_stmt_bind_param($stmt, "s", $param_username);
                    $param_username = $username;
                    if (mysqli_stmt_execute($stmt)) {
                        mysqli_stmt_store_result($stmt);
                        if (mysqli_stmt_num_rows($stmt) == 1) {
                            $username_err = "This username is already registered.";
                        }
                    } else {
                        echo "<script>alert('Oops! Something went wrong. Please try again later.');</script>";
                    }
                    mysqli_stmt_close($stmt);
                }
            }
        }

        if (empty(trim($_POST["email"]))) {
            $email_err = "Please enter an email address.";
        } else {
            $email = filter_var($_POST["email"], FILTER_SANITIZE_EMAIL);
            if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
                $email_err = "Please enter a valid email address.";
            } else {
                $sql = "SELECT id FROM users WHERE email = ?";
                if ($stmt = mysqli_prepare($link, $sql)) {
                    mysqli_stmt_bind_param($stmt, "s", $param_email);
                    $param_email = $email;
                    if (mysqli_stmt_execute($stmt)) {
                        mysqli_stmt_store_result($stmt);
                        if (mysqli_stmt_num_rows($stmt) == 1) {
                            $email_err = "This email is already registered.";
                        }
                    } else {
                        echo "<script>alert('Oops! Something went wrong. Please try again later.');</script>";
                    }
                    mysqli_stmt_close($stmt);
                }
            }
        }

        if (empty(trim($_POST["password"]))) {
            $password_err = "Please enter a password.";
        } else {
            $password = trim($_POST["password"]);
            if (strlen($password) < 8) {
                $password_err = "Password must contain at least 8 or more characters.";
            }
        }

        if (empty($username_err) && empty($email_err) && empty($password_err)) {
            $sql = "INSERT INTO users (username, email, password) VALUES (?, ?, ?)";
            if ($stmt = mysqli_prepare($link, $sql)) {
                mysqli_stmt_bind_param($stmt, "sss", $param_username, $param_email, $param_password);
                $param_username = $username;
                $param_email = $email;
                $param_password = password_hash($password, PASSWORD_DEFAULT);
                if (mysqli_stmt_execute($stmt)) {
                    echo "<script>alert('Registration completed successfully. Login to continue.');</script>";
                    echo "<script>window.location.href='./login.php';</script>";
                    exit;
                } else {
                    echo "<script>alert('Oops! Something went wrong. Please try again later.');</script>";
                }
                mysqli_stmt_close($stmt);
            }
        }
    } else {
        echo "<script>alert('Invalid CSRF token.');</script>";
        echo "<script>window.location.href='./register.php';</script>";
        exit;
    }

    mysqli_close($link);
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta http-equiv="X-UA-Compatible" content="IE=edge">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>User Registration System</title>
  <link rel="stylesheet" href="./css/main.css">
  <link rel="shortcut icon" href="./img/favicon-16x16.png" type="image/x-icon">
  <script defer src="./js/script.js"></script>
  <style>
    body {
      font-family: Arial, sans-serif;
      background-color: #f0f0f0;
    }
    .container {
      max-width: 600px;
      margin: 0 auto;
      padding: 20px;
    }
    .form-wrap {
      background-color: #fff;
      border: 1px solid #ddd;
      padding: 20px;
      border-radius: 5px;
    }
    .form-wrap h1 {
      font-size: 24px;
      margin-bottom: 20px;
    }
    .form-wrap form {
      margin-top: 15px;
    }
    .form-wrap .form-label {
      margin-bottom: 5px;
    }
    .form-wrap .form-control {
      width: 100%;
      height: 40px;
      padding: 8px;
      font-size: 16px;
      border: 1px solid #ccc;
      border-radius: 3px;
    }
    .form-wrap .btn-primary {
      height: 40px;
      font-size: 16px;
      background-color: #007bff;
      border: none;
      color: #fff;
      cursor: pointer;
      transition: background-color 0.3s;
    }
    .form-wrap .btn-primary:hover {
      background-color: #0056b3;
    }
    .form-wrap .text-danger {
      font-size: 14px;
    }
    .mb-3 {
      margin-bottom: 15px;
    }
    .mb-0 {
      margin-bottom: 0;
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="form-wrap border rounded p-4">
      <h1>Sign Up</h1>
      <p>Please fill this form to register</p>
      <form action="<?= htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="post" novalidate>
        <div class="mb-3">
          <label for="username" class="form-label">Username</label>
          <input type="text" class="form-control" name="username" id="username" value="<?= $username; ?>">
          <small class="text-danger"><?= $username_err; ?></small>
        </div>
        <div class="mb-3">
          <label for="email" class="form-label">Email Address</label>
          <input type="email" class="form-control" name="email" id="email" value="<?= $email; ?>">
          <small class="text-danger"><?= $email_err; ?></small>
        </div>
        <div class="mb-2">
          <label for="password" class="form-label">Password</label>
          <input type="password" class="form-control" name="password" id="password" value="<?= $password; ?>">
          <small class="text-danger"><?= $password_err; ?></small>
        </div>
        <div class="mb-3 form-check">
          <input type="checkbox" class="form-check-input" id="togglePassword">
          <label for="togglePassword" class="form-check-label">Show Password</label>
        </div>
        <div class="mb-3">
          <input type="hidden" name="csrf_token" value="<?= $_SESSION['csrf_token']; ?>">
          <input type="submit" class="btn btn-primary form-control" name="submit" value="Sign Up">
        </div>
        <p class="mb-0">Already have an account? <a href="./login.php">Log In</a></p>
      </form>
    </div>
  </div>
</body>
</html>
