<?php
$allowed = ["help" => "show_help", "version" => "show_version"];
$action = "help";
if (isset($allowed[$action])) {
  call_user_func($allowed[$action]);
}
