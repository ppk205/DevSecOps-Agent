<?php
use Firebase\JWT\JWT;
$token = JWT::encode($payload, "supersecret", "HS256");
