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

$cert = $le->acquireCert(["data1.insecure.optools.net", "data2.insecure.optools.net"]);

phore_dir(__DIR__ . "/../demo_cert")->withFileName("data1.insecure.optools.net.json")->set_json((array)$cert);

