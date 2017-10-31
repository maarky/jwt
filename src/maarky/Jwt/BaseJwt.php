<?php

namespace maarky\Jwt;

use TypeError;
use maarky\Option\Option;
use maarky\Option\Type\Callback\Option as CallbackOption;
use maarky\Option\Type\String\Option as StringOption;

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
    protected $validators = null;
    /**
     * Supported hashing algorithms.
     *
     * @var array
     */
    protected $algs = [
        'HS256' => 'sha256',
        'HS384' => 'sha384',
        'HS512' => 'sha512',
    ];
    /**
     * @var bool
     */
    protected $trusted = false;

    public function setSecret($secret): Jwt
    {
        if(is_string($secret) || is_callable($secret)) {
            $this->secret = $secret;
        } else {
            throw new TypeError('$secret must be a string or a callable.');
        }
        return $this;
    }

    public function getSecret(): StringOption
    {
        if(is_callable($this->secret)) {
            $this->secret = (string) ($this->secret)($this);
        }
        return StringOption::new($this->secret);
    }

    public function getHeader(string $key): Option
    {
        return Option::new($this->header[$key]);
    }

    public function getHeaders(): array
    {
        return (array) $this->header;
    }

    /**
     * Get all supported hashing algorithms.
     *
     * @return array
     */
    public function getSupportedAlgs(): array
    {
        return array_keys($this->algs);
    }

    public function getClaim(string $key): Option
    {
        return Option::new($this->claims[$key]);
    }

    public function getClaims(): array
    {
        return (array) $this->claims;
    }

    public function addValidator(string $name, callable $validator): Jwt
    {
        $this->setupValidators();
        $this->validators[$name] = $validator;
        return $this;
    }

    public function removeValidator(string $name): Jwt
    {
        $this->setupValidators();
        unset($this->validators[$name]);
        return $this;
    }

    public function clearValidators(): Jwt
    {
        $this->validators = [];
        return $this;
    }

    public function getValidators(): array
    {
        $this->setupValidators();
        return $this->validators;
    }

    public function getValidator(string $name): CallbackOption
    {
        return CallbackOption::new($this->getValidators()[$name]);
    }

    /**
     * Create default validators if nothing has been set
     */
    protected function setupValidators()
    {
        if(is_array($this->validators)) {
            return $this;
        }
        
        $getTime = function($time) {
            if(is_int($time)) {
                return $time;
            }
            return strtotime($time);
        };
        
        $this->validators = [
            'secret' => function(Jwt $jwt): bool {
                return $jwt->getSecret()->isDefined();
            },
            //algorithm
            'alg' => function(Jwt $jwt): bool {
                return $jwt->getHeader('alg')->filter(function($alg) {
                    return in_array($alg, $this->getSupportedAlgs());
                })->isDefined();
            },
            //type
            'typ' => function(Jwt $jwt): bool {
                return $jwt->getHeader('typ')->filter(function($typ) {
                    return $typ == 'JWT';
                })->isDefined();
            },
            //expiration
            'exp' => function(Jwt $jwt) use($getTime): bool {
                $expiration = $jwt->getClaim('exp');
                if($expiration->isEmpty()) {
                    return true;
                }
                return $expiration->filter(function($time) use($getTime) {
                    return $getTime($time) >= time();
                })->isDefined();
            },
            //not before
            'nbf' => function(Jwt $jwt) use($getTime): bool {
                $notBefore = $jwt->getClaim('nbf');
                if($notBefore->isEmpty()) {
                    return true;
                }
                return $notBefore->filter(function($time) use($getTime) {
                    return $getTime($time) <= time();
                })->isDefined();
            },
            //issued at
            'iat' => function(Jwt $jwt) use($getTime): bool {
                $issuedAt = $jwt->getClaim('iat');
                if($issuedAt->isEmpty()) {
                    return true;
                }
                return $issuedAt->filter(function($time) use($getTime) {
                    return $getTime($time) < time();
                })->isDefined();
            }
        ];
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
            return [];
        }
        return $json;
    }

    public function isValid(): bool
    {
        foreach($this->getValidators() as $validator) {
            if(!$validator($this)) {
                return false;
            }
        }
        return true;
    }

    public function isTrusted(): bool
    {
        return $this->trusted;
    }
}
