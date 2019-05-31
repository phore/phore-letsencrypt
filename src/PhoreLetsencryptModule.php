<?php
/**
 * Created by PhpStorm.
 * User: matthias
 * Date: 31.05.19
 * Time: 15:24
 */

namespace Phore\Letsencrypt;


use Phore\MicroApp\App;
use Phore\MicroApp\AppModule;

class PhoreLetsencryptModule implements AppModule
{


    /**
     * Called just after adding this to a app by calling
     * `$app->addModule(new SomeModule());`
     *
     * Here is the right place to add Routes, etc.
     *
     * @param App $app
     *
     * @return mixed
     */
    public function register(App $app)
    {
        $app->router->onGet("/.well-known/acme-challenge/:key", function(string $key) {



        });
    }
}
