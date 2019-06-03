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

$cert = $le->acquireCert(["data1.insecure.versenkt.de", "data2.insecure.versenkt.de"]);

phore_dir(__DIR__ . "/../demo_cert")->withFileName("data1.insecure.versenkt.de.json")->set_json((array)$cert);

