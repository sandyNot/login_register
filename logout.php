<?php
session_start();

$_SESSION = array();

session_destroy();


if (isset($_COOKIE["remember_me"])) {
    setcookie("remember_me", "", time() - 3600, "/"); 
}
echo "<script>" . "window.location.href='./login.php';" . "</script>";
exit;
