<?php
function findAccountsByOwner($connection, $ownerRef)
{
    $query = "SELECT ref FROM accounts WHERE owner = '" . $ownerRef . "'";
    $rows = mysqli_query($connection, $query);
    $found = array();
    while ($row = mysqli_fetch_assoc($rows)) {
        $found[] = $row['ref'];
    }
    return $found;
}
