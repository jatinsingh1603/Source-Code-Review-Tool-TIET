<?php

function a() {
    // ruleid: php.crypto.insecure-random
    return mt_rand();
}

function b() {
    // ruleid: php.crypto.insecure-random
    return rand(1000, 9999);
}

function c() {
    // ok: php.crypto.insecure-random
    return random_int(1000, 9999);
}
