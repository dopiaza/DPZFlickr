<?php

header("Content-type: text.plain");

$configFile = dirname(__FILE__) . '/config.php';

if (file_exists($configFile))
{
    include $configFile;
}
else
{
    die("Please rename the config-sample.php file to config.php and add your Flickr API key and secret to it\n");
}

require_once dirname(__FILE__) . '/DPZFlickr.php';

$flickr = new DPZFlickr($flickrApiKey, $flickrApiSecret);

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
        <p>You have now signed out of this Flickr session. <a href="example-auth.php">Sign in</a>.</p>
    </body>
</html>