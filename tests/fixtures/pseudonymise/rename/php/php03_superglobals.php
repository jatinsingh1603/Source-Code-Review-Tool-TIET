<?php
function handleLogin()
{
    $userName = $_POST['username'];
    $passPhrase = $_POST['password'];
    if (strlen($userName) > 0) {
        $_SESSION['current_user'] = $userName;
        header("Location: /dashboard");
    }
    return $passPhrase;
}
