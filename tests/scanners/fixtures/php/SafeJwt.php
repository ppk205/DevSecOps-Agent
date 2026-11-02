<?php
use Firebase\JWT\JWT;
$token = JWT::encode($payload, getenv("JWT_SECRET"), "RS256");
