<?php
/**
 * Created by PhpStorm.
 * User: matthias
 * Date: 03.06.19
 * Time: 10:24
 */

namespace Phore\Letsencrypt;

require __DIR__ . "/../vendor/autoload.php";



$le = new PhoreLetsencrypt("matthes@leuffen.de");

$le->acquireCert(["localhost"]);

