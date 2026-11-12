<?php

function a() {
    // ruleid: php.injection.eval
    eval($_POST['code']);
}

function b() {
    // ok: php.injection.eval
    eval("return 1;");
}
