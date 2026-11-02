<?php
$reset_code = mt_rand(100000, 999999);
store_code($user_id, $reset_code);
