<?php
// Intentionally vulnerable fixture: unsanitized request data reaches eval,
// which is exactly what the php-dynamic-eval rule must flag.
eval($_GET['cmd']);
