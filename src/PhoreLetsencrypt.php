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


    public function getConnectedDomains(array $domains) : array
    {
        $connectedDomains = [];
        foreach ($domains as $domain) {
            $domain = strtolower($domain);
            if (!$this->_isHostnameConnected($domain)) {
                continue;
            }
            $connectedDomains[] = $domain;
        }
        return $connectedDomains;
    }


    public function acquireCert (array $domains, array &$errors=[]) : PhoreCert
    {
        $tmppath = phore_dir("/tmp/certbot_" . uniqid());
        $tmppath->mkdir(0700);

        $errors = [];

        $domainParams = [];
        $firstDomain = null;
        $connectedDomains = $this->getConnectedDomains($domains);

        foreach ($connectedDomains as $domain) {
            if ($firstDomain === null)
                $firstDomain = $domain;
            $domainParams[] = "-d " . escapeshellarg($domain);
        }
        if ($firstDomain === null) {
            $errors[] = ["domain" => null, "error" => "no connected domain (Requesting certs for: " . implode(", ", $domains) . ")"];
            throw new \InvalidArgumentException("No domain is mapped to this service: " . implode(", ", $domains));
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
            $proc->setTimeout(120);
            $proc->wait();

            $crtPath = $tmppath->withSubPath("live")->withSubPath($firstDomain);
            $crtPath->assertDirectory();

            $cert = new PhoreCert();
            $cert->domains = $connectedDomains;
            $cert->issued_at = time();
            $cert->cert = $crtPath->withFileName("cert.pem")->get_contents();
            $cert->chain = $crtPath->withFileName("chain.pem")->get_contents();
            $cert->fullchain = $crtPath->withFileName("fullchain.pem")->get_contents();
            $cert->privkey = $crtPath->withFileName("privkey.pem")->get_contents();

            phore_exec("rm -Rf :path", ["path" => $tmppath->getUri()]);
            return $cert;

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
