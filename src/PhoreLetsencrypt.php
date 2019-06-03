<?php
/**
 * Created by PhpStorm.
 * User: matthias
 * Date: 31.05.19
 * Time: 15:23
 */

namespace Phore\Letsencrypt;


use Phore\FileSystem\PhoreDirectory;
use Phore\System\PhoreProc;

class PhoreLetsencrypt
{

    const DEFAULT_LE_ROOT = "/tmp/letsencrypt";

    private $tosEMail;

    private $webroot;

    public function __construct(string $tosEMail, PhoreDirectory $webroot = null)
    {
        if ($webroot === null)
            $webroot = phore_dir(self::DEFAULT_LE_ROOT);
        $webroot->mkdir("0755");
        $this->webroot = $webroot;

        phore_assert($tosEMail)->email();
        $this->tosEMail = $tosEMail;
    }


    protected function _isHostnameConnected(string $hostname) {
        try {
            $ret = phore_http_request("http://$hostname/.well-known/acme-challenge/rudl-host")->send()->getBodyJson();
            if ($ret["hostname"] === gethostname())
                return true;
            return false;
        } catch (\Exception $e) {
            return false;
        }
    }


    public function acquireCert (array $domains, array &$errors=[])
    {
        $tmppath = phore_dir("/tmp/certbot_" . uniqid());
        $tmppath->mkdir(0700);

        $errors = [];

        $domainParams = [];
        $firstDomain = null;
        foreach ($domains as $domain) {
            if ( ! $this->_isHostnameConnected($domain)) {
                $errors[] = ["domain"=>$domain, "error"=>"not connected."];
                continue;
            }
            if ($firstDomain === null)
                $firstDomain = $domain;
            $domainParams[] = "-d " . escapeshellarg($domain);
        }
        if ($firstDomain === null) {
            $errors[] = ["domain" => null, "error" => "no connected domain (Requesting certs for: " . implode(", ", $domains) . ")"];
            return false;
        }

        $domainParams = implode(" ", $domainParams);

        try {


            $proc = new PhoreProc(
                "certbot certonly -n --agree-tos -m :email --logs-dir :path --config-dir :path --work-dir :path --webroot -w :webroot $domainParams",
                [
                    "email" => $this->tosEMail,
                    "path" => $tmppath->getUri(),
                    "webroot" => $this->webroot->getUri()
                ]
            );
            $proc->setTimeout(60);
            $proc->wait();
        } catch (\Exception $e) {
            phore_exec("rm -Rf :path", ["path" => $tmppath->getUri()]);
            throw $e;
        }
    }

    public function getChallengeByKey(string $key) : string
    {
        return $this->webroot->withSubPath(".well-known/acme-challenge")->withFileName($key)->get_contents();
    }



}
