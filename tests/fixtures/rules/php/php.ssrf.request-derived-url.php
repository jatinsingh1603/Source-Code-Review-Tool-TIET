<?php

function a() {
    // ruleid: php.ssrf.request-derived-url
    return curl_init($_GET['url']);
}

function b($h) {
    // ruleid: php.ssrf.request-derived-url
    return curl_setopt($h, CURLOPT_URL, $_POST['u']);
}

function c() {
    // ok: php.ssrf.request-derived-url
    return curl_init("https://api.example.test/v1");
}
