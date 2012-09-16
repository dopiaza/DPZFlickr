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

if (!$flickr->authenticate('write'))
{
    die("Hmm, something went wrong...\n");
}

$message = "";

if (!empty($_POST))
{
    $photoId = @$_POST['photoid'];

    $parameters = array(
        'photo_id' => $photoId,
    );

    $photo = $_FILES['photo'];

    if ($photo['size'] > 0)
    {
        $parameters['photo'] = '@' . $photo['tmp_name'];
    }

    $response = $flickr->replace($parameters);

    $ok = @$response['stat'];

    if ($ok == 'ok')
    {
        $photos = $response['photos'];
        $message = "Photo uploaded";
    }
    else
    {
        $err = @$response['err'];
        $message = "Error: " . @$err['msg'];
    }
}

?>
<!DOCTYPE html>
<html>
<head>
    <title>DPZFlickr Replace Example</title>
    <link rel="stylesheet" href="example.css" />
</head>
<body>
<h1>Replace Photo</h1>
<?php if (!empty($message)) { ?>
    <p class="message"><?php echo $message ?></p>
<?php } ?>

<form id="upload" method="POST" enctype="multipart/form-data">
    <label for="photoid">Photo Id to Replace</label>
    <input id="photoid" name="photoid" type="text" size="20">

    <label for="photo">Attach a photo</label>
    <input id="photo" name="photo" type="file">

    <input id="upload-button" class="submit" type="submit" value="Upload photo">
</form>
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

