<?php

function a() {
    // ruleid: php.deser.unserialize
    return unserialize($_COOKIE['state']);
}

function b($blob) {
    // ruleid: php.deser.unserialize
    return unserialize($blob);
}

function c($blob) {
    // ok: php.deser.unserialize
    return json_decode($blob, true);
}
