<?php
declare(strict_types=1);

namespace maarky\Jwt\Immutable;

use TypeError;
use maarky\Jwt\BaseJwt;
use maarky\Jwt\Mutable\Jwt as MutableJwt;
use maarky\Jwt\Jwt as JwtInterface;
use maarky\Option\Option;
use maarky\Option\Type\Arr\Option as ArrayOption;

class Jwt extends BaseJwt
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

    public function __construct(string $jwt, $secret = null)
    {
        $jwtParts = explode('.', $jwt);
        if(3 != count($jwtParts)) {
            throw new TypeError('Bad JWT');
        }
        $this->jwt = $jwt;
        list($this->encodedHeader, $this->encodedClaims, $this->encodedSignature) = $jwtParts;
        $this->setSecret($secret);
    }

    public function getHeader(string $key): Option
    {
        $this->createHeaders();
        return parent::getHeader($key);
    }

    public function getHeaders(): ArrayOption
    {
        $this->createHeaders();
        return parent::getHeaders();
    }

    public function addHeader(string $key, $value): JwtInterface
    {
        return $this->getMutable()->addHeader($key, $value);
    }

    public function addHeaders(array $headers): JwtInterface
    {
        return $this->getMutable()->addHeaders($headers);
    }

    public function removeHeader(string $key): JwtInterface
    {
        return $this->getMutable()->removeHeaders($key);
    }

    public function setAlgo(string $algo): JwtInterface
    {
        return $this->getMutable()->setAlgo($algo);
    }

    public function setType(string $type): JwtInterface
    {
        return $this->getMutable()->setType($type);
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

    public function getClaims(): ArrayOption
    {
        $this->createClaims();
        return parent::getClaims();
    }

    public function addClaim(string $key, $value): JwtInterface
    {
        return $this->getMutable()->addClaim($key, $value);
    }

    public function addClaims(array $claims): JwtInterface
    {
        return $this->getMutable()->addClaims($claims);
    }

    public function removeClaim(string $key): JwtInterface
    {
        return $this->getMutable()->removeClaim($key);
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
        $algo = $this->algos[$this->getHeader('alg')->get()];
        $signature = $this->encodeBase64(hash_hmac($algo, $jwt, $this->getSecret()->get(), true));
        return $this->encodedSignature == $signature;
    }

    public function getMutable(): MutableJwt
    {
        $jwt = new MutableJwt($this->getClaims()->get(), null, $this->getHeaders()->get());
        if(!is_null($this->secret)) {
            $jwt->setSecret($this->getSecret()->get());
        }
        $validators = $this->getValidators();
        if($validators->isDefined()) {
            $jwt->addValidator(...$validators->get());
        }
        return $jwt;
    }

    public function getImmutable(): Jwt
    {
        return $this;
    }
}