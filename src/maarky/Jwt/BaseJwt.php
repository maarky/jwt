<?php

namespace maarky\Jwt;

use TypeError;
use maarky\Option\Option;
use maarky\Option\Some;
use maarky\Option\None;
use maarky\Option\Type\String\Option as StringOption;
use maarky\Option\Type\String\Some as StringSome;
use maarky\Option\Type\String\None as StringNone;
use maarky\Option\Type\Int\Some as IntSome;
use maarky\Option\Type\Int\None as IntNone;
use maarky\Option\Type\Arr\Option as ArrayOption;
use maarky\Option\Type\Arr\Some as ArraySome;
use maarky\Option\Type\Arr\None as ArrayNone;

abstract class BaseJwt implements Jwt
{
    /**
     * @var string
     */
    protected $secret;
    /**
     * @var array
     */
    protected $header;
    /**
     * @var array
     */
    protected $claims;
    /**
     * @var array
     */
    protected $validators = [];
    /**
     * Supported hashing algorithms.
     *
     * @var array
     */
    protected $algos = [
        'HS256' => 'sha256',
        'HS384' => 'sha384',
        'HS512' => 'sha512',
    ];
    /**
     *
     *
     * @var bool
     */
    protected $trusted = true;

    public function setSecret($secret): Jwt
    {
        if(is_string($secret) || is_callable($secret)) {
            $this->secret = $secret;
        } elseif(!is_null($secret)) {
            throw new TypeError('$secret must be a string or a callable.');
        }
        return $this;
    }

    public function getSecret(): StringOption
    {
        if(is_null($this->secret)) {
            return new StringNone;
        }
        if(is_callable($this->secret)) {
            $function = $this->secret;
            $this->secret = (string) $function($this);
        }
        return new StringSome($this->secret);
    }

    public function getHeader(string $key): Option
    {
        if(!array_key_exists($key, $this->header)) {
            return new None;
        }
        return new Some($this->header[$key]);
    }

    public function getHeaders(): ArrayOption
    {
        return new ArraySome($this->header);
    }

    /**
     * Get all supported hashing algorithms.
     *
     * @return array
     */
    public function getSupportedAlgos(): array
    {
        return array_keys($this->algos);
    }

    public function getClaim(string $key): Option
    {
        if(!array_key_exists($key, $this->claims)) {
            return new None;
        }
        return new Some($this->claims[$key]);
    }

    public function getClaims(): ArrayOption
    {
        return new ArraySome($this->claims);
    }

    /**
     * Add multiple validators.
     *
     * @param \callable[] ...$validators
     * @return Jwt
     */
    public function addValidator(callable ...$validators): Jwt
    {
        foreach($validators as $validator) {
            $this->validators[] = $validator;
        }
        return $this;
    }

    /**
     * Get a list of all custom validators.
     * @return ArrayOption
     */
    public function getValidators(): ArrayOption
    {
        if(empty($this->validators)) {
            return new ArrayNone;
        }
        return new ArraySome($this->validators);
    }

    protected function encodeBase64($data): string {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    protected function decodeBase64(string $encoded): string
    {
        return base64_decode(str_pad(strtr($encoded, '-_', '+/'), strlen($encoded) % 4, '=', STR_PAD_RIGHT));
    }

    protected function decodeJson(string $encoded): array
    {
        $json = json_decode($this->decodeBase64($encoded), true);
        if(is_null($json)) {
            throw new TypeError('Bad JSON');
        }
        return $json;
    }

    public function isValid(): bool
    {
        $secret = $this->getSecret();
        if($secret->isEmpty()) {
            return false;
        }
        $headers = $this->getHeaders();
        if(
            $headers->filter(function(array $headers) {
                return count($headers) > 1;
            })->filter(function(array $headers) {
                return !empty($headers['alg']) && array_key_exists($headers['alg'], $this->algos);
            })->filter(function(array $headers) {
                return !empty($headers['typ']) && $headers['typ'] == 'JWT';
            })->isEmpty()
        ) {
            return false;
        }

        $now = time();
        $getTime = function($time) {
            if(!is_int($time)) {
                $time = strtotime($time);
            }
            return new IntSome($time);
        };
        $expires = $this->getClaim('exp')->flatMap($getTime);
        if(
            $expires->isDefined() &&
            $expires->filter(function(int $expiration) use($now) {
                return $now < $expiration;
            })->isEmpty()
        ) {
            return false;
        }
        $notBefore = $this->getClaim('nbf')->flatMap($getTime);
        if(
            $notBefore->isDefined() &&
            $notBefore->filter(function(int $nbf) use($now) {
                return $now > $nbf;
            })->isEmpty()
        ) {
            return false;
        }
        $issuedAt = $this->getClaim('iat')->flatMap($getTime);
        if(
            $issuedAt->isDefined() &&
            $issuedAt->flatMap($getTime)
                ->filter(function(int $iat) use($now) {
                    return $now > $iat;
                })->isEmpty()
        ) {
            return false;
        }
        if($issuedAt->isDefined() && $notBefore->isDefined() &&
            $issuedAt->filter(function(int $iat) use($notBefore) {
                return $iat < $notBefore->get();
            })->isEmpty()
        ) {
            return false;
        }

        foreach($this->validators as $validator) {
            if(!$validator($this)) {
                return false;
            }
        }

        return true;
    }

    public function isTrusted()
    {
        return $this->trusted;
    }
}