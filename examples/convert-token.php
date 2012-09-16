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

$token = $_POST['token'];

if (!empty($token))
{
    $flickr->convertOldToken($token);
}


?>
<!DOCTYPE html>
<html>
    <head>
        <title>DPZFlickr Convert Token Example</title>
        <link rel="stylesheet" href="example.css" />
    </head>
    <body>
        <h1>Convert Token</h1>

        <form action="<?php echo $_SERVER['SCRIPT_NAME'] ?>" method="post">
            <input type="text" size="50" name="token" />
            <input type="submit" value="Convert Token" />
        </form>
    <?php if (!empty($token)) { ?>
            <p>
                NSID: <?php echo $flickr->getOauthData(Flickr::USER_NSID) ?><br />
                User Name: <?php echo $flickr->getOauthData(Flickr::USER_NAME) ?><br />
                Full Name: <?php echo $flickr->getOauthData(Flickr::USER_FULL_NAME) ?><br />
                Access Token: <?php echo $flickr->getOauthData(Flickr::OAUTH_ACCESS_TOKEN) ?><br />
                Access Token Secret: <?php echo $flickr->getOauthData(Flickr::OAUTH_ACCESS_TOKEN_SECRET) ?>
            </p>
    <?php } ?>
        <p><a href="index.php">Unauthenticated Example</a> |
            <a href="auth.php">Authenticated Example</a> |
            <a href="convert-token.php">Convert Token Example</a> <br/>
            <a href="upload.php">Upload Photo Example</a> |
            <a href="replace.php">Replace Photo Example</a>
        </p>
    </body>
</html>
