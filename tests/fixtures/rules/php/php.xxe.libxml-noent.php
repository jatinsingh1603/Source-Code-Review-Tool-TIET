<?php

function a($xml) {
    // ruleid: php.xxe.libxml-noent
    return simplexml_load_string($xml, 'SimpleXMLElement', LIBXML_NOENT);
}

function b($d, $xml) {
    // ruleid: php.xxe.libxml-noent
    return $d->loadXML($xml, LIBXML_NOENT | LIBXML_DTDLOAD);
}

function c($d, $xml) {
    // ok: php.xxe.libxml-noent
    return $d->loadXML($xml, LIBXML_NONET);
}
