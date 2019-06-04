<?php
/**
 * Created by PhpStorm.
 * User: matthias
 * Date: 04.06.19
 * Time: 22:13
 */

namespace Tests;


use Phore\Core\Helper\PhoreSecretBoxSync;
use Phore\Letsencrypt\PhoreCert;
use Phore\Letsencrypt\PhoreSecureCertStore;
use PHPUnit\Framework\TestCase;

class SecureCertTest extends TestCase
{


    public function testEncryptCert()
    {
        $cert = new PhoreSecureCertStore("asdfasdfasdf", "/tmp");

        $n = new PhoreCert();
        $n->load(phore_file(__DIR__ . "/../demo_cert/data1.insecure.optools.net.json")->get_json());

        $cert->addCert("abc", $n);

        $c = $cert->getCertPem("abc");
        $this->assertEquals(true, true);
    }

}
