<?php
session_start();
require_once 'db_connect.php';

function registerUser($name, $email, $username, $password)
{
  global $conn;
  $hashed_password = password_hash($password, PASSWORD_DEFAULT);
  $stmt = $conn->prepare("INSERT INTO users (name, email, username, password) VALUES (?,?,?,?)");
  $stmt->bind_param("ssss", $name, $email, $username, $hashed_password);
  return $stmt->execute();
}

function loginUser($username, $password)
{
  global $conn;
  $stmt = $conn->prepare("SELECT * FROM users WHERE username =?");
  $stmt->bind_param("s", $username);
  $stmt->execute();
  $result = $stmt->get_result();

  if ($result->num_rows === 1) {
    $user = $result->fetch_assoc();
    if (password_verify($password, $user['password'])) {
      $_SESSION['user_id'] = $user['id'];
      $_SESSION['user_name'] = $user['name'];
      return true;
    }
  }

  return false;
}

function getAllUsers()
{
  global $conn;
  $stmt = $conn->prepare("SELECT * FROM users");
  $stmt->execute();
  $result = $stmt->get_result();
  return $result->fetch_all(MYSQLI_ASSOC);
}

function deleteUser($id)
{
  global $conn;
  $stmt = $conn->prepare("DELETE FROM users WHERE id =?");
  $stmt->bind_param("i", $id);
  return $stmt->execute();
}

function updateUser($id, $name, $email, $username, $password = null)
{
  global $conn;
  $set_clause = "name=?, email=?, username=?";

  if (!is_null($password)) {
    $hashed_password = password_hash($password, PASSWORD_DEFAULT);
    $set_clause.= ", password=?";
  }

  $stmt = $conn->prepare("UPDATE users SET $set_clause WHERE id=?");
  $stmt->bind_param("ssssi", $name, $email, $username, $hashed_password?? '', $id);
  return $stmt->execute();
}
?>