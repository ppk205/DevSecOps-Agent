<?php
$reset_code = random_int(100000, 999999);
store_code($user_id, $reset_code);
