<?php
/**
 * Created by PhpStorm.
 * User: matthias
 * Date: 31.05.19
 * Time: 15:23
 */

namespace Phore\Letsencrypt;


use Phore\FileSystem\PhoreDirectory;

class PhoreLetsencrypt
{


    private $tosEMail;

    private $webroot;

    public function __construct(PhoreDirectory $webroot)
    {
        $this->webroot = $webroot;
    }


    public function acquireCert (array $domains)
    {
        $tmppath = phore_dir("/tmp/certbot_" . uniqid());
        $tmppath->mkdir(0700);

        $domainParams = [];
        foreach ($domains as $domain) {
            $domainParams[] = "-d " . escapeshellarg($domain);
        }
        $domainParams = implode(" ", $domainParams);

        try {
            phore_exec(
                "certbot certonly -n --agree-tos -m :email --logs-dir :path --config-dir :path --test-cert --dry-run --work-dir :path --webroot -w :webroot $domainParams",
                [
                    "email" => $this->tosEMail,
                    "path" => $tmppath->getUri(),
                    "webroot" => $this->webroot->getUri()
                ]
            );
        } catch (\Exception $e) {
            phore_exec("rm -R :path", ["path" => $tmppath->getUri()]);
            throw $e;
        }
    }

    public function getChallengeByKey(string $key) : string
    {
        return $this->webroot->withSubPath(".well-known/acme-challenge")->withFileName($key)->get_contents();
    }



}
