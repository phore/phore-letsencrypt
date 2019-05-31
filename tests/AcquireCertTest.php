<?php
/**
 * Created by PhpStorm.
 * User: matthias
 * Date: 31.05.19
 * Time: 16:48
 */

namespace Tests;


use Phore\Letsencrypt\PhoreLetsencrypt;
use PHPUnit\Framework\TestCase;

class AcquireCertTest extends TestCase
{


    public function testAcquireCert()
    {
        $le = new PhoreLetsencrypt("info@someurl.com");
        $le->acquireCert(["certtest.leuffen.de"]);
    }

}
