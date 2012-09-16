<?php

/**
 * Flickr API Kit with support for OAuth 1.0a for PHP >= 5.1.2. Requires curl.
 *
 * Author: David Wilkinson
 * Web: http://dopiaza.org/
 *
 * Copyright (c) 2012 David Wilkinson
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
 * documentation files (the "Software"), to deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all copies or substantial portions of
 * the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
 * WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS
 * OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
 * OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 */

namespace DPZ;

class Flickr
{
    const VERSION = 1.2;

    /**
     * Session variable name used to store authentication data
     */
    const SESSION_OAUTH_DATA = 'FlickrSessionOauthData';

    /**
     * Key names for various authentication data items
     */
    const OAUTH_REQUEST_TOKEN = 'oauth_request_token';
    const OAUTH_REQUEST_TOKEN_SECRET = 'oauth_request_token_secret';
    const OAUTH_VERIFIER = 'oauth_verifier';
    const OAUTH_ACCESS_TOKEN = 'oauth_access_token';
    const OAUTH_ACCESS_TOKEN_SECRET = 'oauth_access_token_secret';
    const USER_NSID = 'user_nsid';
    const USER_NAME = 'user_name';
    const USER_FULL_NAME = 'user_full_name';
    const PERMISSIONS = 'permissions';
    const IS_AUTHENTICATING = 'is_authenticating';

    /**
     * Default timeout in seconds for HTTP requests
     */
    const DEFAULT_HTTP_TIMEOUT = 30;

    /**
     * Various API endpoints
     */
    const REQUEST_TOKEN_ENDPOINT = 'http://www.flickr.com/services/oauth/request_token';
    const AUTH_ENDPOINT = 'http://www.flickr.com/services/oauth/authorize';
    const ACCESS_TOKEN_ENDPOINT = 'http://www.flickr.com/services/oauth/access_token';
    const API_ENDPOINT = 'http://www.flickr.com/services/rest';
    const UPLOAD_ENDPOINT = 'http://www.flickr.com/services/upload/';
    const REPLACE_ENDPOINT = 'http://www.flickr.com/services/replace/';

    /**
     * @var string Flickr API key
     */
    private $consumerKey;

    /**
     * @var string Flickr API secret
     */
    private $consumerSecret;

    /**
     * @var string Callback URI for authentication
     */
    private $callback;

    /**
     * @var string HTTP Method to use for API calls
     */
    private $method = 'POST';

    /**
     * @var int HTTP Response code for last call made
     */
    private $lastHttpResponseCode;

    /**
     * @var int Timeout in seconds for HTTP calls
     */
    private $httpTimeout;

    /**
     * Create a new Flickr object
     *
     * @param string $key The Flickr API key
     * @param string $secret The Flickr API secret
     * @param string $callback The callback URL for authentication
     */
    public function __construct($key, $secret = NULL, $callback = NULL)
    {
        session_start();

        $this->consumerKey = $key;
        $this->consumerSecret = $secret;
        $this->callback = $callback;

        $this->httpTimeout = self::DEFAULT_HTTP_TIMEOUT;
    }

    /**
     * Call a Flickr API method
     *
     * @param string $method The FLickr API method name
     * @param array $parameters The method parameters
     * @return mixed|null The response object
     */
    public function call($method, $parameters = NULL)
    {
        $requestParams = ($parameters == NULL ? array() : $parameters);
        $requestParams['method'] = $method;
        $requestParams['format'] = 'php_serial';

        $requestParams = array_merge($requestParams, $this->getOauthParams());

        $requestParams['oauth_token'] = $this->getOauthData(self::OAUTH_ACCESS_TOKEN);
        $this->sign(self::API_ENDPOINT, $requestParams);

        $response = $this->httpRequest(self::API_ENDPOINT, $requestParams);

        return empty($response) ? NULL : unserialize($response);
    }

    /**
     * Upload a photo
     * @param $parameters
     * @return mixed|null
     */
    public function upload($parameters)
    {
        $requestParams = ($parameters == NULL ? array() : $parameters);

        $requestParams = array_merge($requestParams, $this->getOauthParams());

        $requestParams['oauth_token'] = $this->getOauthData(self::OAUTH_ACCESS_TOKEN);

        // We don't want to include the photo when signing the request
        // so temporarily remove it whilst we sign
        $photo = $requestParams['photo'];
        unset($requestParams['photo']);
        $this->sign(self::UPLOAD_ENDPOINT, $requestParams);
        $requestParams['photo'] = $photo;

        $xml = $this->httpRequest(self::UPLOAD_ENDPOINT, $requestParams);

        $response = $this->getResponseFromXML($xml);

        return empty($response) ? NULL : $response;
    }

    /**
     * Replace a photo
     * @param $parameters
     * @return mixed|null
     */
    public function replace($parameters)
    {
        $requestParams = ($parameters == NULL ? array() : $parameters);

        $requestParams = array_merge($requestParams, $this->getOauthParams());

        $requestParams['oauth_token'] = $this->getOauthData(self::OAUTH_ACCESS_TOKEN);

        // We don't want to include the photo when signing the request
        // so temporarily remove it whilst we sign
        $photo = $requestParams['photo'];
        unset($requestParams['photo']);
        $this->sign(self::REPLACE_ENDPOINT, $requestParams);
        $requestParams['photo'] = $photo;

        $xml = $this->httpRequest(self::REPLACE_ENDPOINT, $requestParams);

        $response = $this->getResponseFromXML($xml);

        return empty($response) ? NULL : $response;
    }

    /**
     * Initiate the authentication process. Note that this method might not return - the user may get redirected to
     * Flickr to approve the request.
     *
     * @param string $permissions The permissions requested: read, write or delete
     */
    public function authenticate($permissions = 'read')
    {
        $ok = false;
        // First of all, check to see if we're part way through the authentication process
        if ($this->getOauthData(self::IS_AUTHENTICATING))
        {
            $oauthToken = @$_GET['oauth_token'];
            $oauthVerifier = @$_GET['oauth_verifier'];

            if (!empty($oauthToken) && !empty($oauthVerifier))
            {
                // Looks like we're in the callback
                $this->setOauthData(self::OAUTH_REQUEST_TOKEN, $oauthToken);
                $this->setOauthData(self::OAUTH_VERIFIER, $oauthVerifier);
                $ok = $this->obtainAccessToken();
            }

            $this->setOauthData(self::IS_AUTHENTICATING, false);
        }

        $ok = ($this->isAuthenticated() && $this->doWeHaveGoodEnoughPermissions($permissions));

        if (!$ok)
        {
            // We're authenticating afresh, clear out the session just in case there are remnants of a
            // previous authentication in there
            $this->signout();

            if ($this->obtainRequestToken())
            {
                // We've got the request token, redirect to Flickr for authentication/authorisation
                // Make a note in the session of where we are first
                $this->setOauthData(self::IS_AUTHENTICATING, true);
                $this->setOauthData(self::PERMISSIONS, $permissions);

                header(sprintf('Location: %s?oauth_token=%s&perms=%s',
                    self::AUTH_ENDPOINT,
                    $this->getOauthData(self::OAUTH_REQUEST_TOKEN),
                    $permissions
                ));
                exit(0);
            }
        }

        return $ok;
    }

    /**
     * Sign the current user out of the current Flickr session. Note this doesn't affect the user's state on the
     * Flickr web site itself, it merely removes the current request/access tokens from the session.
     *
     */
    public function signout()
    {
        unset($_SESSION[self::SESSION_OAUTH_DATA]);
    }

    /**
     * Is the current session authenticated on Flickr
     *
     * @return bool the current authentication status
     */
    public function isAuthenticated()
    {
        $authNSID = $this->getOauthData(self::USER_NSID);
        return !empty($authNSID);
    }

    /**
     * Return a value from the OAuth session data
     *
     * @param string $key
     * @return string value
     */
    public function getOauthData($key)
    {
        $val = NULL;
        $data = @$_SESSION[self::SESSION_OAUTH_DATA];
        if (is_array($data))
        {
            $val = @$data[$key];
        }
        return $val;
    }

    /**
     * Return the HTTP Response code for the last HTTP call made
     *
     * @return int
     */
    public function getLastHttpResponseCode()
    {
        return $this->lastHttpResponseCode;
    }

    /**
     * Set the timeout for HTTP requests
     *
     * @param int $timeout
     */
    public function setHttpTimeout($timeout)
    {
        $this->httpTimeout = $timeout;
    }


    /**
     * Convert an old authentication token into an OAuth access token
     *
     * @param string $token
     */
    public function convertOldToken($token)
    {
        $param = array(
            'method' => 'flickr.auth.oauth.getAccessToken',
            'format' => 'php_serial',
            'api_key' => $this->consumerKey,
            'auth_token' => $token
            );

        $this->signUsingOldStyleAuth($param);

        $rsp = $this->httpRequest(self::API_ENDPOINT, $param);
        $response = unserialize($rsp);

        if (@$response['stat'] == 'ok')
        {
            $accessToken = @$response['auth']['access_token']['oauth_token'];
            $accessTokenSecret = @$response['auth']['access_token']['oauth_token_secret'];
            $this->setOauthData(self::OAUTH_ACCESS_TOKEN, $accessToken);
            $this->setOauthData(self::OAUTH_ACCESS_TOKEN_SECRET, $accessTokenSecret);

            $response = $this->call('flickr.auth.oauth.checkToken');
            if (@$response['stat'] == 'ok')
            {
                $this->setOauthData(self::USER_NSID, @$response['oauth']['user']['nsid']);
                $this->setOauthData(self::USER_NAME, @$response['oauth']['user']['username']);
                $this->setOauthData(self::USER_FULL_NAME, @$response['oauth']['user']['fullname']);
            }
        }
    }

    /**
     * Sign an array of parameters using the old-style auth method
     *
     * @param array $parameters
     */
    private function signUsingOldStyleAuth(&$parameters)
    {
        $keys = array_keys($parameters);
        sort($keys, SORT_STRING);
        $s = $this->consumerSecret;
        foreach ($keys as $k)
        {
            $s .= $k . $parameters[$k];
        }

        $parameters['api_sig'] = md5($s);
    }

    private function setOauthData($key, $value)
    {
        $data = @$_SESSION[self::SESSION_OAUTH_DATA];
        if (!is_array($data))
        {
            $data = array();
        }
        $data[$key] = $value;
        $_SESSION[self::SESSION_OAUTH_DATA] = $data;
    }

    /**
     * Check whether the current permission satisfy those requested
     *
     * @param string $permissionsRequired
     * @return bool
     */
    private function doWeHaveGoodEnoughPermissions($permissionsRequired)
    {
        $ok = false;

        $currentPermissions = $this->getOauthData(self::PERMISSIONS);

        switch($permissionsRequired)
        {
            case 'read':
                $ok = preg_match('/^(read|write|delete)$/', $currentPermissions);
                break;

            case 'write':
                $ok = preg_match('/^(write|delete)$/', $currentPermissions);
                break;

            case 'delete':
                $ok = ($currentPermissions == 'delete');
                break;
        }

        return $ok;
    }

    /**
     * Get a request token from Flickr
     *
     * @return bool
     */
    private function obtainRequestToken()
    {
        $params = $this->getOauthParams();
        $params['oauth_callback'] = $this->callback;

        $this->sign(self::REQUEST_TOKEN_ENDPOINT, $params);

        $rsp = $this->httpRequest(self::REQUEST_TOKEN_ENDPOINT, $params);
        $responseParameters = $this->splitParameters($rsp);
        $callbackOK = (@$responseParameters['oauth_callback_confirmed'] == 'true');

        if ($callbackOK)
        {
            $this->setOauthData(self::OAUTH_REQUEST_TOKEN, @$responseParameters['oauth_token']);
            $this->setOauthData(self::OAUTH_REQUEST_TOKEN_SECRET, @$responseParameters['oauth_token_secret']);
        }

        return $callbackOK;
    }

    /**
     * Get an access token from Flickr
     *
     * @return bool
     */
    private function obtainAccessToken()
    {
        $params = $this->getOauthParams();
        $params['oauth_token'] = $this->getOauthData(self::OAUTH_REQUEST_TOKEN);
        $params['oauth_verifier'] = $this->getOauthData(self::OAUTH_VERIFIER);

        $this->sign(self::ACCESS_TOKEN_ENDPOINT, $params);

        $rsp = $this->httpRequest(self::ACCESS_TOKEN_ENDPOINT, $params);

        $responseParameters = $this->splitParameters($rsp);
        $ok = !empty($responseParameters['oauth_token']);

        if ($ok)
        {
            $this->setOauthData(self::OAUTH_ACCESS_TOKEN, @$responseParameters['oauth_token']);
            $this->setOauthData(self::OAUTH_ACCESS_TOKEN_SECRET, @$responseParameters['oauth_token_secret']);
            $this->setOauthData(self::USER_NSID, @$responseParameters['user_nsid']);
            $this->setOauthData(self::USER_NAME, @$responseParameters['username']);
            $this->setOauthData(self::USER_FULL_NAME, @$responseParameters['fullname']);
        }

        return $ok;
    }

    /**
     * Split a string into an array of key-value pairs
     *
     * @param string $string
     * @return array
     */
    private function splitParameters($string)
    {
        $parameters = array();
        $keyValuePairs = explode('&', $string);
        foreach ($keyValuePairs as $kvp)
        {
            $pieces = explode('=', $kvp);
            if (count($pieces) == 2)
            {
                $parameters[rawurldecode($pieces[0])] = rawurldecode($pieces[1]);
            }
        }
        return $parameters;
    }

    /**
     * Join an array of parameters together into a URL-encoded string
     *
     * @param array $parameters
     * @return string
     */
    private function joinParameters($parameters)
    {
        $keys = array_keys($parameters);
        sort($keys, SORT_STRING);
        $keyValuePairs = array();
        foreach ($keys as $k)
        {
            array_push($keyValuePairs, rawurlencode($k) . "=" . rawurlencode($parameters[$k]));
        }

        return implode("&", $keyValuePairs);
    }

    /**
     * Get the base string for creating an OAuth signature
     *
     * @param string $method
     * @param string $url
     * @param array $parameters
     * @return string
     */
    private function getBaseString($method, $url, $parameters)
    {
        $components = array(
                    rawurlencode($method),
                    rawurlencode($url),
                    rawurlencode($this->joinParameters($parameters))
            );

        $baseString = implode("&", $components);

        return $baseString;
    }

    /**
     * Sign an array of parameters with an OAuth signature
     *
     * @param string $url
     * @param array $parameters
     */
    private function sign($url, &$parameters)
    {
        $baseString = $this->getBaseString($this->method, $url, $parameters);
        $signature  = $this->getSignature($baseString);
        $parameters['oauth_signature'] = $signature;
    }

    /**
     * Calculate the signature for a string
     *
     * @param string $string
     * @return string
     */
    private function getSignature($string)
    {
        $keyPart1 = $this->consumerSecret;
        $keyPart2 = $this->getOauthData(self::OAUTH_ACCESS_TOKEN_SECRET);
        if (empty($keyPart2))
        {
            $keyPart2 = $this->getOauthData(self::OAUTH_REQUEST_TOKEN_SECRET);
        }
        if (empty($keyPart2))
        {
            $keyPart2 = '';
        }

        $key = "$keyPart1&$keyPart2";

        return base64_encode(hash_hmac('sha1', $string, $key, true));
    }

    /**
     * Get the standard OAuth parameters
     *
     * @return array
     */
    private function getOauthParams()
    {
        $params = array (
            'oauth_nonce' => $this->makeNonce(),
            'oauth_timestamp' => time(),
            'oauth_consumer_key' => $this->consumerKey,
            'oauth_signature_method' => 'HMAC-SHA1',
            'oauth_version' => '1.0',
        );

        return $params;
    }

    /**
     * Create a nonce
     *
     * @return string
     */
    private function makeNonce()
    {
        // Create a string that will be unique for this app and this user at this time
        $reasonablyDistinctiveString = implode(':',
            array(
                $this->consumerKey,
                $this->getOauthData(self::USER_NSID),
                microtime()
            )
        );

        return md5($reasonablyDistinctiveString);
    }

    /**
     * Get the response structure from an XML response.
     * Annoyingly, upload and replace returns XML rather than serialised PHP.
     * The responses are pretty simple, so rather than depend on an XML parser we'll fake it and
     * decode using regexps
     * @param $xml
     * @return mixed
     */
    private function getResponseFromXML($xml)
    {
        $rsp = array();
        $stat = 'fail';
        $matches = array();
        preg_match('/<rsp stat="(ok|fail)">/s', $xml, $matches);
        if (count($matches) > 0)
        {
            $stat = $matches[1];
        }
        if ($stat == 'ok')
        {
            // do this in individual steps in case the order of the attributes ever changes
            $rsp['stat'] = $stat;
            $photoid = array();
            $matches = array();
            preg_match('/<photoid.*>(\d+)<\/photoid>/s', $xml, $matches);
            if (count($matches) > 0)
            {
                $photoid['_content'] = $matches[1];
            }
            $matches = array();
            preg_match('/<photoid.* secret="(\w+)".*>/s', $xml, $matches);
            if (count($matches) > 0)
            {
                $photoid['secret'] = $matches[1];
            }
            $matches = array();
            preg_match('/<photoid.* originalsecret="(\w+)".*>/s', $xml, $matches);
            if (count($matches) > 0)
            {
                $photoid['originalsecret'] = $matches[1];
            }
            $rsp['photoid'] = $photoid;
        }
        else
        {
            $rsp['stat'] = 'fail';
            $err = array();
            $matches = array();
            preg_match('/<err.* code="([^"]*)".*>/s', $xml, $matches);
            if (count($matches) > 0)
            {
                $err['code'] = $matches[1];
            }
            $matches = array();
            preg_match('/<err.* msg="([^"]*)".*>/s', $xml, $matches);
            if (count($matches) > 0)
            {
                $err['msg'] = $matches[1];
            }
            $rsp['err'] = $err;
        }
        return $rsp;
    }

    /**
     * Make an HTTP request
     *
     * @param string $url
     * @param array $parameters
     * @return mixed
     */
    private function httpRequest($url, $parameters)
    {
        $curl = curl_init();

        curl_setopt($curl, CURLOPT_RETURNTRANSFER, TRUE);
        curl_setopt($curl, CURLOPT_TIMEOUT, $this->httpTimeout);

        if ($this->method == 'POST')
        {
            curl_setopt($curl, CURLOPT_URL, $url);
            curl_setopt($curl, CURLOPT_POST, TRUE);
            curl_setopt($curl, CURLOPT_POSTFIELDS, $parameters);
        }
        else
        {
            // Assume GET
            curl_setopt($curl, CURLOPT_URL, "$url?" . $this->joinParameters($parameters));
        }

        $response = curl_exec($curl);
        $headers = curl_getinfo($curl);

        curl_close($curl);

        $this->lastHttpResponseCode = $headers['http_code'];

        return $response;
    }
}
