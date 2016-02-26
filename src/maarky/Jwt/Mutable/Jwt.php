<?php

namespace maarky\Jwt\Mutable;

use TypeError;
use maarky\Jwt\BaseJwt;
use maarky\Jwt\Immutable\Jwt as ImmutableJwt;
use maarky\Jwt\Jwt as JwtInterface;

class Jwt extends BaseJwt
{

    public function __construct(array $claims = [], $secret = null, array $header = [])
    {
        if(!array_key_exists('typ', $header)) {
            $header['typ'] = 'JWT';
        }
        if(!array_key_exists('alg', $header)) {
            $header['alg'] = 'HS256';
        }
        $this->header = $header;
        $this->claims = $claims;
        $this->setSecret($secret);
        $this->trusted = false;
    }

    public function addHeader(string $key, $value): JwtInterface
    {
        $this->removeHeader($key);
        $this->header[$key] = $value;
        return $this;
    }

    public function addHeaders(array $headers): JwtInterface
    {
        foreach ($headers as $key => $value) {
            $this->addHeader($key, $value);
        }
        return $this;
    }

    public function removeHeader(string $key): JwtInterface
    {
        unset($this->header[$key]);
        return $this;
    }

    public function setAlgo(string $algo): JwtInterface
    {
        return $this->addHeader('alg', $algo);
    }

    public function setType(string $type): JwtInterface
    {
        return $this->addHeader('typ', $type);
    }

    public function addClaim(string $key, $value): JwtInterface
    {
        $this->claims[$key] = $value;
        return $this;
    }

    public function addClaims(array $claims): JwtInterface
    {
        foreach ($claims as $key => $value) {
            $this->addClaim($key, $value);
        }
        return $this;
    }

    public function removeClaim(string $key): JwtInterface
    {
        unset($this->claims[$key]);
        return $this;
    }

    public function encode(): string
    {
        $algo = $this->getHeader('alg');
        if($algo->isEmpty()) {
            throw new Exception(Exception::ENCODE_WITHOUT_ALG);
        }
        $claims = $this->getClaims();
        if($claims->isEmpty()) {
            throw new Exception(Exception::ENCODE_WITHOUT_CLAIMS);
        }
        $secret = $this->getSecret();
        if($secret->filter(function($secret) { return !empty($secret); })->isEmpty()) {
            throw new Exception(Exception::ENCODE_WITHOUT_SECRET);
        }

        $header = $this->encodeBase64(json_encode($this->getHeaders()->get()));
        $claims = $this->encodeBase64(json_encode($claims->get()));
        $jwt = $header . '.' . $claims;
        $algo = $this->algos[$algo->get()];
        $signature = hash_hmac($algo, $jwt, $secret->get(), true);
        return $jwt . '.' . $this->encodeBase64($signature);
    }

    public function getMutable(): Jwt
    {
        return $this;
    }

    public function getImmutable(): ImmutableJwt
    {
        $jwt = new ImmutableJwt($this->encode());
        if(!is_null($this->secret)) {
            $jwt->setSecret($this->getSecret()->get());
        }
        $validators = $this->getValidators();
        if($validators->isDefined()) {
            $jwt->addValidator(...$validators->get());
        }
        $jwt->trusted = false;
        return $jwt;
    }
}