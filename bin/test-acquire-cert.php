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

$cert = $le->acquireCert(["localhost"]);

phore_dir(__DIR__ . "/../demo_cert")->withFileName("test1.demo-org.tld")->set_json($cert);

