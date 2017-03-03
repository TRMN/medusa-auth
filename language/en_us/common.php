<?php

if (!defined('IN_PHPBB'))
{
    exit;
}

if (empty($lang) || !is_array($lang))
{
    $lang = array();
}

$lang = array_merge($lang, [
    'MEDUSA_NO_USER_INFO' => 'MEDUSA user information not available.',
]);

