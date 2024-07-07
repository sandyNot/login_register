<?php
session_start();

if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

if (isset($_SESSION["loggedin"]) && $_SESSION["loggedin"] === true) {
    echo "<script>window.location.href='./'</script>";
    exit;
}

require_once "./config.php";

$user_login_err = $user_password_err = $login_err = "";
$user_login = $user_password = "";
$remember_me_checked = false;

if (isset($_COOKIE['user_id']) && isset($_COOKIE['user_key'])) {
    $user_id = $_COOKIE['user_id'];
    $user_key = $_COOKIE['user_key'];

    $sql = "SELECT id, username, password FROM users WHERE id = ?";
    if ($stmt = mysqli_prepare($link, $sql)) {
        mysqli_stmt_bind_param($stmt, "i", $user_id);
        if (mysqli_stmt_execute($stmt)) {
            mysqli_stmt_store_result($stmt);
            if (mysqli_stmt_num_rows($stmt) == 1) {
                mysqli_stmt_bind_result($stmt, $id, $username, $hashed_password);
                if (mysqli_stmt_fetch($stmt)) {
                    if (password_verify($user_key, $hashed_password)) {
                        $_SESSION["id"] = $id;
                        $_SESSION["username"] = $username;
                        $_SESSION["loggedin"] = true;
                        echo "<script>window.location.href='./'</script>";
                        exit;
                    }
                }
            }
        }
        mysqli_stmt_close($stmt);
    }
}

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    if (empty(trim($_POST["user_login"]))) {
        $user_login_err = "Please enter your username or email.";
    } else {
        $user_login = trim($_POST["user_login"]);
    }

    if (empty(trim($_POST["user_password"]))) {
        $user_password_err = "Please enter your password.";
    } else {
        $user_password = trim($_POST["user_password"]);
    }

    $remember_me = isset($_POST["remember_me"]);

    if (empty($user_login_err) && empty($user_password_err)) {
        if (hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
            $sql = "SELECT id, username, password FROM users WHERE username = ? OR email = ?";
            if ($stmt = mysqli_prepare($link, $sql)) {
                mysqli_stmt_bind_param($stmt, "ss", $user_login, $user_login);
                if (mysqli_stmt_execute($stmt)) {
                    mysqli_stmt_store_result($stmt);
                    if (mysqli_stmt_num_rows($stmt) == 1) {
                        mysqli_stmt_bind_result($stmt, $id, $username, $hashed_password);
                        if (mysqli_stmt_fetch($stmt)) {
                            if (password_verify($user_password, $hashed_password)) {
                                $_SESSION["id"] = $id;
                                $_SESSION["username"] = $username;
                                $_SESSION["loggedin"] = true;

                                if ($remember_me) {
                                    setcookie('user_id', $id, time() + (86400 * 30), "/");
                                    setcookie('user_key', $hashed_password, time() + (86400 * 30), "/");
                                    setcookie('user_login', $user_login, time() + (86400 * 30), "/");
                                    setcookie('user_password', $user_password, time() + (86400 * 30), "/");
                                } else {
                                    setcookie('user_id', '', time() - 3600, "/");
                                    setcookie('user_key', '', time() - 3600, "/");
                                    setcookie('user_login', '', time() - 3600, "/");
                                    setcookie('user_password', '', time() - 3600, "/");
                                }

                                echo "<script>window.location.href='./'</script>";
                                exit;
                            } else {
                                $login_err = "The email or password you entered is incorrect.";
                            }
                        }
                    } else {
                        $login_err = "Invalid username or password.";
                    }
                } else {
                    echo "<script>alert('Oops! Something went wrong. Please try again later.');</script>";
                    echo "<script>window.location.href='./login.php'</script>";
                    exit;
                }
                mysqli_stmt_close($stmt);
            }
        } else {
            echo "<script>alert('Invalid CSRF token.');</script>";
            echo "<script>window.location.href='./login.php'</script>";
            exit;
        }
    }
    mysqli_close($link);
}

if (isset($_COOKIE['user_login'])) {
    $user_login = $_COOKIE['user_login'];
    $remember_me_checked = true;
}
if (isset($_COOKIE['user_password'])) {
    $user_password = $_COOKIE['user_password'];
    $remember_me_checked = true;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta http-equiv="X-UA-Compatible" content="IE=edge">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>User Login System</title>
  <link rel="stylesheet" href="./css/main.css">
  <link rel="shortcut icon" href="./img/favicon-16x16.png" type="image/x-icon">
  <script defer src="./js/script.js"></script>
</head>
<body>
  <div class="container">
    <div class="login-box">
      <?php if (!empty($login_err)) {
        echo "<div class='alert'>" . $login_err . "</div>";
      } ?>
      <h1>Log In</h1>
      <p>Please log in to continue</p>
      <form action="<?= htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="post" novalidate>
        <div class="form-group">
          <label for="user_login">Email or username</label>
          <input type="text" name="user_login" id="user_login" value="<?= isset($user_login) ? htmlspecialchars($user_login) : ''; ?>">
          <small class="error"><?= $user_login_err; ?></small>
        </div>
        <div class="form-group">
          <label for="password">Password</label>
          <input type="password" name="user_password" id="password" value="<?= isset($user_password) ? htmlspecialchars($user_password) : ''; ?>">
          <small class="error"><?= $user_password_err; ?></small>
        </div>
        <div class="form-group">
          <input type="checkbox" id="togglePassword">
          <label for="togglePassword">Show Password</label>
        </div>
        <div class="form-group">
          <input type="checkbox" id="remember_me" name="remember_me" <?= $remember_me_checked ? 'checked' : ''; ?>>
          <label for="remember_me">Remember Me</label>
        </div>
        <div class="form-group">
          <input type="hidden" name="csrf_token" value="<?= $_SESSION['csrf_token']; ?>">
          <input type="submit" name="submit" value="Log In">
        </div>
        <p>Don't have an account? <a href="./register.php">Sign Up</a></p>
      </form>
    </div>
  </div>
</body>
</html>
