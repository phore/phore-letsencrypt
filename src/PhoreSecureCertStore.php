<?php
/**
 * Created by PhpStorm.
 * User: matthias
 * Date: 04.06.19
 * Time: 13:47
 */

namespace Phore\Letsencrypt;


use Phore\Core\Helper\PhoreSecretBoxSync;

class PhoreSecureCertStore
{
    const INDEX_FILE = "cert.index.json";

    const RENEW_CERT_GRACE_TIME = 60 * 5;          // 15 minutes Change the cert after this time if new Domains appeared
    const RENEW_CERT_BEFORE_EXPIRES = 28 * 86400;   // 28 Days before expires
    const RENEW_CERT_ERROR_RECOVERY_TIME = 60 * 15; // 15 minutes after failure
    /**
     * @var \Phore\FileSystem\PhoreDirectory
     */
    private $path;

    /**
     * @var PhoreSecretBoxSync
     */
    private $secretBox;

    /**
     * @var array
     */
    private $indexData;
    /**
     * @var \Phore\FileSystem\PhoreFile
     */
    private $indexFile;

    public function __construct(string $encryptSecret, string $rootDir = "/mnt/ssl")
    {
        $this->path = phore_dir($rootDir)->assertDirectory(true);
        $this->secretBox = new PhoreSecretBoxSync($encryptSecret);
        if ( ! $this->path->withFileName(self::INDEX_FILE)->isFile())
            $this->path->withFileName(self::INDEX_FILE)->asFile()->set_json(["__errors__" => []]);
        $this->indexFile = $this->path->withFileName(self::INDEX_FILE)->assertFile();
        $this->indexData = $this->indexFile->get_json();
    }

    public function addCert (string $name, PhoreCert $cert)
    {

        $data = $this->indexData;

        $cert->parse();
        $data[$name] = [
            "domains" => $cert->domains,
            "issued_at" => $cert->issued_at,
            "cert_validTo" => $cert->cert_validTo,
            "cert_validFrom" => $cert->cert_validFrom,
            "cert_serialNumber" => $cert->cert_serialNumber,
            "cert_hash" => $cert->cert_hash
        ];
        $this->indexData = $data;
        $this->path->withFileName($name, "enc")->set_contents($this->secretBox->encrypt($cert->getPemFullcain()));
        $this->indexFile->set_json($data);
    }


    public function getCertPem (string $name) : ?string
    {
        $file = $this->path->withFileName($name , "enc");
        if ( ! $file->exists())
            return null;
        $data = $file->get_contents();
        return $this->secretBox->decrypt($data);
    }

    public function getCertMeta(string $name) : ?PhoreCertMeta
    {
        if ( ! $this->path->withFileName($name, "enc")->exists())
            return null;
        if ( ! isset ($this->indexData[$name]))
            return null;
        $meta = new PhoreCertMeta();
        $meta->load($this->indexData[$name]);
        return $meta;
    }


    private function _hasConnectableDomains(PhoreCertMeta $meta, array $domains, PhoreLetsencrypt $letsencrypt) : bool
    {
        $missingDomains = [];
        foreach ($domains as $curDomain) {
            $curDomain = strtolower($curDomain);
            if (!in_array($curDomain, $meta->domains))
                $missingDomains[] = $curDomain;
        }

        if (count ($missingDomains) === 0)
            return false;

        $connectableDomains = $letsencrypt->getConnectedDomains($missingDomains);
        if (count ($connectableDomains) > 0)
            return true;
        return false;
    }


    public function _setError (string $name, array $domains, string $msg)
    {
        if ( ! isset ($this->indexData["__errors__"]))
            $this->indexData["__errors__"] = [];
        $this->indexData["__errors__"][$name] = [
            "time" => time(),
            "domains" => $domains,
            "msg" => $msg
        ];
        $this->indexFile->set_json($this->indexData);
    }

    public function _unsetError (string $name)
    {
        if (isset ($this->indexData["__errors__"]) && isset ($this->indexData["__errors__"][$name]))
            unset ($this->indexData["__errors__"][$name]);
        $this->indexFile->set_json($this->indexData);
    }


    public function getErrors() : array
    {
        return phore_pluck("__errors__", $this->indexData, []);
    }


    public function acquireCertIfNeeded(string $name, array $domains, PhoreLetsencrypt $letsencrypt)
    {
        if (phore_pluck(["__errors__", $name, "time"], $this->indexData, 0) > time() - self::RENEW_CERT_ERROR_RECOVERY_TIME) {
            phore_out("No issue: in error recovery time.");
            return false;
        }


        $meta = $this->getCertMeta($name);
        if ($meta instanceof PhoreCertMeta) {
            $mustReissue = false;
            if ($meta->issued_at > time() - self::RENEW_CERT_GRACE_TIME) {
                phore_out("No issue: Issued at smaller renew grace time");
                return false;
            }

            if ($this->_hasConnectableDomains($meta, $domains, $letsencrypt)) {
                phore_out("Reissue: Has new connectalbe Domains");
                $mustReissue = true;
            }

            if ( $meta->cert_validTo < time() + self::RENEW_CERT_BEFORE_EXPIRES) {
                phore_out("Reissue: Domain expire in <28 days");
                $mustReissue = true;
            }

            if ( ! $mustReissue) {
                return false;
            }
        }
        try {
            $cert = $letsencrypt->acquireCert($domains);
            $this->addCert($name, $cert);
            $this->_unsetError($name);
        } catch (\Exception $e) {
            $this->_setError($name, $domains, $e->getMessage());
            throw $e;
        }
    }

}
