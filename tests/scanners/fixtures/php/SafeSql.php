<?php
$pdo = new PDO("mysql:host=localhost;dbname=shop", "app", "secret");
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
$stmt->execute([$_GET['id']]);
