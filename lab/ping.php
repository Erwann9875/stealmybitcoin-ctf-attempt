<?php
header('Content-Type: text/plain; charset=utf-8');
header('Cache-Control: no-store');

if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['message'] ?? null) === 'ping') {
    echo "pong\n";
    return;
}

http_response_code(400);
echo "Send message=ping to receive pong.\n";

