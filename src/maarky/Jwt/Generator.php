<?php

namespace maarky\Jwt;

use maarky\Jwt\Jwt as JwtInterface;

class Generator extends BaseJwt
{
    public function __construct(array $claims = [], $secret = null, array $header = [])
    {
        if(!array_key_exists('typ', $header)) {
            $header['typ'] = 'JWT';
        }
        if(!array_key_exists('alg', $header)) {
            $header['alg'] = $this->getSupportedAlgs()[0];
        }
        $this->header = $header;
        $this->claims = $claims;
        if(!is_null($secret)) {
            $this->setSecret($secret);
        }
    }

    public function addHeader(string $key, $value): JwtInterface
    {
        $this->header[$key] = $value;
        return $this;
    }

    public function removeHeader(string $key): JwtInterface
    {
        unset($this->header[$key]);
        return $this;
    }

    public function setAlg(string $alg): JwtInterface
    {
        return $this->addHeader('alg', $alg);
    }

    public function addClaim(string $key, $value): JwtInterface
    {
        $this->claims[$key] = $value;
        return $this;
    }

    public function removeClaim(string $key): JwtInterface
    {
        unset($this->claims[$key]);
        return $this;
    }

    public function encode(): string
    {
        $alg = $this->getHeader('alg');
        if($alg->isEmpty()) {
            throw new Exception(Exception::ENCODE_WITHOUT_ALG);
        }
        $claims = $this->getClaims();
        if(empty($claims)) {
            throw new Exception(Exception::ENCODE_WITHOUT_CLAIMS);
        }
        $secret = $this->getSecret();
        if($secret->filter(function($secret) { return !empty($secret); })->isEmpty()) {
            throw new Exception(Exception::ENCODE_WITHOUT_SECRET);
        }

        $header = $this->encodeBase64(json_encode($this->getHeaders()));
        $claims = $this->encodeBase64(json_encode($claims));
        $jwt = $header . '.' . $claims;
        $alg = $this->algs[$alg->get()];
        $signature = hash_hmac($alg, $jwt, $secret->get(), true);
        return $jwt . '.' . $this->encodeBase64($signature);
    }
}