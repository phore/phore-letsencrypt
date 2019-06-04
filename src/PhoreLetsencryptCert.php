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

    public function load(array $input)
    {
        foreach ($this as $key => $val) {
            $this->$key = phore_pluck($key, $input);
        }
    }

    public $domains = [];
    public $issued_at;
    public $cert;
    public $chain;
    public $fullchain;
    public $privkey;

    public function parse() : bool
    {
        $data = openssl_x509_parse($this->fullchain . "\n" . $this->privkey);
        if ($data === false)
            throw new \InvalidArgumentException("Cannot parse certificate data");
        $this->cert_hash = $data["hash"];
        $this->cert_validFrom = $data["validFrom_time_t"];
        $this->cert_validTo = $data["validTo_time_t"];
        $this->cert_serialNumber = $data["serialNumber"];
        return true;
    }

    public $cert_serialNumber;
    public $cert_hash;
    public $cert_validFrom;
    public $cert_validTo;



}
