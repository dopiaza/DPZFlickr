<?php

$configFile = dirname(__FILE__) . '/config.php';

if (file_exists($configFile))
{
    include $configFile;
}
else
{
    die("Please rename the config-sample.php file to config.php and add your Flickr API key and secret to it\n");
}

spl_autoload_register(function($className)
{
    $className = str_replace ('\\', DIRECTORY_SEPARATOR, $className);
    include (dirname(__FILE__) . '/../src/' . $className . '.php');
});

use \DPZ\Flickr;

$flickr = new Flickr($flickrApiKey, $flickrApiSecret);

$flickr->signout();

?>
<!DOCTYPE html>
<html>
    <head>
        <title>DPZFlickr Auth Signout Example</title>
        <link rel="stylesheet" href="example.css" />
    </head>
    <body>
        <h1>Signed out</h1>
        <p>You have now signed out of this Flickr session. <a href="auth.php">Sign in</a>.</p>
        <p><a href="index.php">Unauthenticated Example</a> |
            <a href="auth.php">Authenticated Example</a> |
            <a href="convert-token.php">Convert Token Example</a> <br/>
            <a href="upload.php">Upload Photo Example</a> |
            <a href="replace.php">Replace Photo Example</a>
        </p>
    </body>
</html>