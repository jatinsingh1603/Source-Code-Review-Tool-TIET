<?php

function a($p) {
    // ruleid: php.crypto.weak-hash
    return md5($p);
}

function b($p) {
    // ruleid: php.crypto.weak-hash
    return sha1($p);
}

function c($p) {
    // ok: php.crypto.weak-hash
    return hash('sha256', $p);
}
