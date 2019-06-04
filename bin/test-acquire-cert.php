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

$secureStore = new PhoreSecureCertStore("SECRET_KEY");

$secureStore->acquireCertIfNeeded("cert1", ["data1.insecure.optools.net", "data2.insecure.optools.net"], $le);

phore_out("Errors");
print_r ($secureStore->getErrors());

phore_out("Metadata");
print_r ($secureStore->getCertMeta("cert1"));

phore_out("Cert");
echo $secureStore->getCertPem("cert1");


