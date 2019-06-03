<?php
/**
 * Created by PhpStorm.
 * User: matthias
 * Date: 31.05.19
 * Time: 17:06
 */

namespace App;

use Phore\Letsencrypt\PhoreLetsencryptModule;
use Phore\MicroApp\App;
use Phore\MicroApp\Handler\JsonExceptionHandler;
use Phore\MicroApp\Handler\JsonResponseHandler;
use PHPUnit\Util\Json;

require __DIR__ . "/../vendor/autoload.php";


$app = new App();
$app->setOnExceptionHandler(new JsonExceptionHandler());
$app->setResponseHandler(new JsonResponseHandler());

$app->acl->addRule(aclRule("*")->ALLOW());

$app->addModule(new PhoreLetsencryptModule());

$app->serve();
