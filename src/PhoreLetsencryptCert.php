<?php
/**
 * Created by PhpStorm.
 * User: matthias
 * Date: 03.06.19
 * Time: 11:44
 */

namespace Phore\Letsencrypt;


class PhoreLetsencryptCert
{

    public $domains = [];
    public $issued_at;
    public $cert;
    public $chain;
    public $fullchain;
    public $privkey;

}
