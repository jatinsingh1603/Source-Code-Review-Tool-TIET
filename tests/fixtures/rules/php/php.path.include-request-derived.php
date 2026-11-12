<?php

function a() {
    // ruleid: php.path.include-request-derived
    return file_get_contents($_GET['f']);
}

function b($name) {
    // ruleid: php.path.include-request-derived
    return file_get_contents("/var/data/" . $name);
}

function c() {
    // ok: php.path.include-request-derived
    return file_get_contents("/var/data/fixed.txt");
}
