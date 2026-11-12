<?php

function a($host) {
    // ruleid: php.injection.shell-exec
    return shell_exec("ping -c1 " . $host);
}

function b() {
    // ruleid: php.injection.shell-exec
    return system($_GET['cmd']);
}

function c() {
    // ok: php.injection.shell-exec
    return shell_exec("uptime");
}
