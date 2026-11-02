<?php
$conn = mysqli_connect("localhost", "app", "secret", "shop");
$id = intval($_GET['id']);
$sql = "SELECT * FROM users WHERE id = " . $id;
$result = mysqli_query($conn, $sql);
