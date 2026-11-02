<?php
$out = preg_replace_callback("/.*/", function ($m) { return strtoupper($m[0]); }, $sub);
save($out);
