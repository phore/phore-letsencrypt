<?php
/**
 * Created by PhpStorm.
 * User: matthias
 * Date: 04.06.19
 * Time: 13:50
 */

namespace Phore\Letsencrypt;


class PhoreCertMeta
{
    public $domains = [];
    public $issued_at;
    public $cert_serialNumber;
    public $cert_hash;
    public $cert_validFrom;
    public $cert_validTo;

    public function load(array $input)
    {
        foreach ($this as $key => $val) {
            $this->$key = phore_pluck($key, $input);
        }
    }
}
