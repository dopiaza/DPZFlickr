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

require_once dirname(__FILE__) . '/DPZFlickr.php';

$flickr = new DPZFlickr($flickrApiKey, $flickrApiSecret);

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
                NSID: <?php echo $flickr->getOauthData(DPZFlickr::USER_NSID) ?><br />
                User Name: <?php echo $flickr->getOauthData(DPZFlickr::USER_NAME) ?><br />
                Full Name: <?php echo $flickr->getOauthData(DPZFlickr::USER_FULL_NAME) ?><br />
                Access Token: <?php echo $flickr->getOauthData(DPZFlickr::OAUTH_ACCESS_TOKEN) ?><br />
                Access Token Secret: <?php echo $flickr->getOauthData(DPZFlickr::OAUTH_ACCESS_TOKEN_SECRET) ?>
            </p>
    <?php } ?>
    </body>
</html>
