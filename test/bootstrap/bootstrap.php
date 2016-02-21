<?php

require __DIR__ . '/../../vendor/autoload.php';

$autoload = new Composer\Autoload\ClassLoader();
$autoload->add('Vagabond', __DIR__ . '/../../lib');
$autoload->register();

$autoload = new Composer\Autoload\ClassLoader();
$autoload->add('Test', __DIR__ . '/../');
$autoload->register();