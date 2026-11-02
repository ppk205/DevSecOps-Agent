<?php
$conn = mysqli_connect("localhost", "app", "secret", "shop");
$id = $_GET['id'];
$sql = "SELECT * FROM users WHERE id = " . $id;
$result = mysqli_query($conn, $sql);
