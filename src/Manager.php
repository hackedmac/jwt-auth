<?php

/*
 * This file is part of jwt-auth.
 *
 * (c) Sean Tymon <tymon148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tymon\JWTAuth;

use Tymon\JWTAuth\Support\RefreshFlow;
use Tymon\JWTAuth\Support\CustomClaims;
use Tymon\JWTAuth\Exceptions\JWTException;
use Tymon\JWTAuth\Exceptions\TokenWhitelistedException;
use Tymon\JWTAuth\Contracts\Providers\JWT as JWTContract;

class Manager
{
    use CustomClaims, RefreshFlow;

    /**
     * The provider.
     *
     * @var \Tymon\JWTAuth\Contracts\Providers\JWT
     */
    protected $provider;



    /**
     * The whitelist.
     *
     * @var \Tymon\JWTAuth\Whitelist
     */
    protected $whitelist;

    /**
     * the payload factory.
     *
     * @var \Tymon\JWTAuth\Factory
     */
    protected $payloadFactory;


    /**
     * the persistent claims.
     *
     * @var array
     */
    protected $persistentClaims = [];

    /**
     * Constructor.
     *
     * @param  \Tymon\JWTAuth\Contracts\Providers\JWT  $provider
     * @param  \Tymon\JWTAuth\Whitelist  $whitelist
     * @param  \Tymon\JWTAuth\Factory  $payloadFactory
     *
     * @return void
     */
    public function __construct(JWTContract $provider, Whitelist $whitelist, Factory $payloadFactory)
    {
        $this->provider = $provider;
        $this->whitelist = $whitelist;
        $this->payloadFactory = $payloadFactory;
    }

    /**
     * Encode a Payload and return the Token.
     *
     * @param  \Tymon\JWTAuth\Payload  $payload
     *
     * @return \Tymon\JWTAuth\Token
     */
    public function encode(Payload $payload)
    {
        $token = $this->provider->encode($payload->get());
        $refreshToken = new Token($token);
        $this->validate($refreshToken);
        return $refreshToken;
    }

    /**
     * Decode a Token and return the Payload.
     *
     * @param  \Tymon\JWTAuth\Token  $token
     *
     * @throws \Tymon\JWTAuth\Exceptions\TokenWhitelistedException
     *
     * @return \Tymon\JWTAuth\Payload
     */
    public function decode(Token $token)
    {
        $payloadArray = $this->provider->decode($token->get());

        $payload = $this->payloadFactory
                        ->setRefreshFlow($this->refreshFlow)
                        ->customClaims($payloadArray)
                        ->make();

        if (!$this->whitelist->has($payload)) {
            throw new TokenWhitelistedException('The token has not been stored');
        }

        return $payload;
    }

    /**
     * Decode a Token and return the Payload.
     *
     * @param  \Tymon\JWTAuth\Token  $token
     *
     *
     * @return \Tymon\JWTAuth\Payload
     */
    public function saveDecode(Token $token)
    {
        $payloadArray = $this->provider->decode($token->get());

        $payload = $this->payloadFactory
            ->setRefreshFlow($this->refreshFlow)
            ->customClaims($payloadArray)
            ->make();

        return $payload;
    }

    /**
     * Refresh a Token and return a new Token.
     *
     * @param  \Tymon\JWTAuth\Token  $token
     *
     * @throws \Tymon\JWTAuth\Exceptions\TokenWhitelistedException
     *
     * @return \Tymon\JWTAuth\Token
     */
    public function refresh(Token $token)
    {
        $this->setRefreshFlow();

        $claims = $this->buildRefreshClaims($this->decode($token));

        $this->invalidate($token);

        // make a new token
        $refreshToken = $this->encode(
            $this->payloadFactory->customClaims($claims)->make(false)
        );

        return $refreshToken;
    }

    /**
     * Invalidate a Token by removing it from whitelist.
     *
     * @param  \Tymon\JWTAuth\Token  $token
     *
     * @throws \Tymon\JWTAuth\Exceptions\TokenWhitelistedException
     *
     * @return bool
     */
    public function invalidate(Token $token)
    {
        return call_user_func(
            [$this->whitelist, 'remove'],
            $this->decode($token)
        );
    }

    /**
     * validate a Token by adding it to the whitelist.
     *
     * @param  \Tymon\JWTAuth\Token  $token
     *
     * @throws \Tymon\JWTAuth\Exceptions\TokenWhitelistedException
     *
     * @return bool
     */
    public function validate(Token $token)
    {
        return call_user_func(
            [$this->whitelist, 'add'],
            $this->saveDecode($token)
        );
    }

    /**
     * Build the claims to go into the refreshed token.
     *
     * @param  \Tymon\JWTAuth\Payload  $payload
     *
     * @return array
     */
    protected function buildRefreshClaims(Payload $payload)
    {
        // assign the payload values as variables for use later
        extract($payload->toArray());

        // persist the relevant claims
        return array_merge(
            $this->customClaims,
            compact($this->persistentClaims, 'sub', 'iat')
        );
    }

    /**
     * Get the Payload Factory instance.
     *
     * @return \Tymon\JWTAuth\Factory
     */
    public function getPayloadFactory()
    {
        return $this->payloadFactory;
    }

    /**
     * Get the JWTProvider instance.
     *
     * @return \Tymon\JWTAuth\Contracts\Providers\JWT
     */
    public function getJWTProvider()
    {
        return $this->provider;
    }

    /**
     * Get the Blacklist instance.
     *
     * @return \Tymon\JWTAuth\Whitelist
     */
    public function getWhitelist()
    {
        return $this->whitelist;
    }



    /**
     * Set the claims to be persisted when refreshing a token.
     *
     * @param  array  $claims
     *
     * @return $this
     */
    public function setPersistentClaims(array $claims)
    {
        $this->persistentClaims = $claims;

        return $this;
    }
}
