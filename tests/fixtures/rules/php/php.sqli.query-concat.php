<?php

function a($c, $id) {
    // ruleid: php.sqli.query-concat
    return mysqli_query($c, "SELECT * FROM t WHERE id = " . $id);
}

function b($pdo, $id) {
    // ruleid: php.sqli.query-concat
    return $pdo->query("SELECT * FROM t WHERE id = $id");
}

function c($pdo, $id) {
    $st = $pdo->prepare("SELECT * FROM t WHERE id = ?");
    // ok: php.sqli.query-concat
    return $st->execute([$id]);
}
