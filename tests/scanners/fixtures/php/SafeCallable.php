<?php
$allowed = ["trim" => true, "strtolower" => true];
$fn = "trim";
if (isset($allowed[$fn])) {
  echo call_user_func($fn, "  X  ");
}
