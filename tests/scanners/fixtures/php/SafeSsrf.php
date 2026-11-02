<?php
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, "https://api.example.com/data");
$response = curl_exec($ch);
