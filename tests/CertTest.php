<?php
/**
 * Created by PhpStorm.
 * User: matthias
 * Date: 03.06.19
 * Time: 12:24
 */

namespace Tests;


use Phore\Letsencrypt\PhoreCert;
use PHPUnit\Framework\TestCase;

class CertTest extends TestCase
{


    public function testGetCertData()
    {
        $cert = new PhoreCert();
        $cert->load(phore_file(__DIR__ . "/../demo_cert/data1.insecure.optools.net.json")->get_json());
        $cert->parse();

        echo $cert->fullchain . "\n" . $cert->privkey;

        $this->assertEquals(1567329646, $cert->cert_validTo);
    }



}
