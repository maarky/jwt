<?php
declare(strict_types=1);

namespace maarky\Jwt;

use TypeError;
use maarky\Option\Option;

class Validator extends BaseJwt
{
    /**
     * @var string
     */
    protected $jwt;
    /**
     * @var string
     */
    protected $encodedClaims;
    /**
     * @var string
     */
    protected $encodedHeader;
    /**
     * @var string
     */
    protected $encodedSignature;
    /**
     * @var bool
     */
    protected $trusted = true;

    public function __construct(string $jwt, $secret = null)
    {
        $jwtParts = explode('.', $jwt);
        if(3 != count($jwtParts)) {
            throw new TypeError('Bad JWT');
        }
        $this->jwt = $jwt;
        list($this->encodedHeader, $this->encodedClaims, $this->encodedSignature) = $jwtParts;
        if(null != $secret) {
            $this->setSecret($secret);
        }
    }

    public function getHeader(string $key): Option
    {
        $this->createHeaders();
        return parent::getHeader($key);
    }

    public function getHeaders(): array
    {
        $this->createHeaders();
        return parent::getHeaders();
    }

    protected function createHeaders()
    {
        if(is_null($this->header)) {
            $this->header = $this->decodeJson($this->encodedHeader);
        }
    }

    public function getClaim(string $key): Option
    {
        $this->createClaims();
        return parent::getClaim($key);
    }

    public function getClaims(): array
    {
        $this->createClaims();
        return parent::getClaims();
    }

    protected function createClaims()
    {
        if(is_null($this->claims)) {
            $this->claims = $this->decodeJson($this->encodedClaims);
        }
    }

    public function encode(): string
    {
        return $this->jwt;
    }

    public function isValid(): bool
    {
        if(!parent::isValid()) {
            return false;
        }

        $jwt = $this->encodedHeader . '.' . $this->encodedClaims;
        $alg = $this->algs[$this->getHeader('alg')->get()];
        $signature = $this->encodeBase64(hash_hmac($alg, $jwt, $this->getSecret()->get(), true));
        return $this->encodedSignature === $signature;
    }

    public function getGenerator(): Generator
    {
        $jwt = new Generator($this->getClaims(), null, $this->getHeaders());
        if(!is_null($this->secret)) {
            $jwt->setSecret($this->getSecret()->get());
        }
        foreach ($this->getValidators() as $name => $validator) {
            $jwt->addValidator($name, $validator);
        }
        return $jwt;
    }
}