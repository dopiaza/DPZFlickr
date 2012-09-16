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

// Build the URL for the current page and use it for our callback
$callback = sprintf('%s://%s:%d%s',
    (@$_SERVER['HTTPS'] == "on") ? 'https' : 'http',
    $_SERVER['SERVER_NAME'],
    $_SERVER['SERVER_PORT'],
    $_SERVER['SCRIPT_NAME']
    );

$flickr = new Flickr($flickrApiKey, $flickrApiSecret, $callback);

if (!$flickr->authenticate('read'))
{
    die("Hmm, something went wrong...\n");
}

$userNsid = $flickr->getOauthData(Flickr::USER_NSID);
$userName = $flickr->getOauthData(Flickr::USER_NAME);
$userFullName = $flickr->getOauthData(Flickr::USER_FULL_NAME);

$parameters =  array(
    'per_page' => 100,
    'extras' => 'url_sq,path_alias',
);

$response = $flickr->call('flickr.stats.getPopularPhotos', $parameters);

$ok = @$response['stat'];

if ($ok == 'ok')
{
    $photos = $response['photos'];
}
else
{
    $err = @$response['err'];
    die("Error: " . @$err['msg']);
}

?>
<!DOCTYPE html>
<html>
    <head>
        <title>DPZFlickr Auth Example</title>
        <link rel="stylesheet" href="example.css" />
    </head>
    <body>
        <h1>Popular photos from <?php echo $userName ?></h1>
        <ul id="photos">
            <?php foreach ($photos['photo'] as $photo) { ?>
                <li>
                    <a href="<?php echo sprintf("http://flickr.com/photos/%s/%s/", $photo['pathalias'], $photo['id']) ?>">
                        <img src="<?php echo $photo['url_sq'] ?>" />
                    </a>
                </li>
            <?php } ?>
        </ul>
        <p class="signout"><a href="signout.php">Sign
            out</a></p>

        <p><a href="index.php">Unauthenticated Example</a> |
            <a href="auth.php">Authenticated Example</a> |
            <a href="convert-token.php">Convert Token Example</a> <br/>
            <a href="upload.php">Upload Photo Example</a> |
            <a href="replace.php">Replace Photo Example</a>
        </p>
    </body>
</html>

