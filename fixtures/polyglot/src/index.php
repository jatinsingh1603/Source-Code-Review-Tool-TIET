<?php
$host = $_GET['host'];
system('ping ' . $host);  // PG-VULN-004
