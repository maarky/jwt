<?php
declare(strict_types=1);

namespace maarky\Jwt;

use maarky\Option\Option;
use maarky\Option\Some;
use maarky\Option\None;
use maarky\Option\Type\String\Option as StringOption;
use maarky\Option\Type\String\Some as StringSome;
use maarky\Option\Type\String\None as StringNone;
use maarky\Option\Type\Arr\Option as ArrayOption;
use maarky\Option\Type\Arr\Some as ArraySome;
use maarky\Option\Type\Arr\None as ArrayNone;

class Jwt
{
    protected $algos = [
        'HS256' => 'sha256',
        'HS384' => 'sha384',
        'HS512' => 'sha512',
    ];
    protected $header = [];
    protected $claims;
    /**
     * @var string
     */
    protected $sourceJwt;
    /**
     * @var string/callable
     */
    protected $secret;
    protected $validators = [];

    /**
     * Jwt constructor.
     *
     * If $input is a string it must be a jwt.
     * if $input is an array it allows the following keys:
     *      claims: an array of claims
     *      header: an array of headers
     *      algo: a string equal to "HS256", "HS384" or "HS512"
     *
     * $input must not contain an algo key if providing a header with an algo key.
     *
     * @param array $input
     * @param string $secret
     * @throws Exception
     */
    public function __construct($input = [], $secret = '')
    {
        if(!empty($secret)) {
            if(!is_string($secret) && !is_callable($secret)) {
                throw new Exception(Exception::ENCODE_WITHOUT_SECRET);
            }
            $this->setSecret($secret);
        }
        if(is_string($input)) {
            $this->sourceJwt = $input;
            $parts = explode('.', $input);
            $this->header = $this->decodeJson($parts[0]);
            $this->claims = $this->decodeJson($parts[1]);
        } else {
            if(!is_array($input)) {
                throw new Exception(Exception::UNSUPPORTED_CONSTRUCTOR_INPUT);
            } else {
                if(!empty($input['claims'])) {
                    $this->addClaims($input['claims']);
                }
                if(!empty($input['header']) && !empty($input['algo'])) {
                    throw new Exception(Exception::CONSTRUCTOR_WITH_DOUBLE_ALGO);
                }
                if(!empty($input['algo'])) {
                    $this->setAlgo($input['algo']);
                }
                if(!empty($input['header'])) {
                    $this->addHeaders($input['header']);
                }
            }
        }
    }

    protected function encodeBase64(string $input)
    {
        return str_replace('=', '', strtr(base64_encode($input), '+/', '-_'));
    }

    protected function decodeBase64(string $input)
    {
        $decoded = base64_decode($input, true);
        if(false === $decoded) {
            throw new Exception(Exception::CANNOT_DECODE_BASE64);
        }
        return $decoded;
    }

    protected function decodeJson(string $json)
    {
        $decoded = $this->decodeBase64($json);
        $json = json_decode($decoded, true);
        if(null == $json) {
            throw new Exception(Exception::CANNOT_DECODE_JSON);
        }
        return $json;
    }

    /**
     * Get the JWT used to create this object, if available.
     *
     * @return StringOption
     */
    public function getSourceJwt(): StringOption
    {
        if(null == $this->sourceJwt) {
            return new StringNone();
        }
        return new StringSome($this->sourceJwt);
    }

    /**
     * Get all headers.
     *
     * @return ArrayOption
     */
    public function getHeaders(): ArrayOption
    {
        if(empty($this->header)) {
            return new ArrayNone;
        }
        return new ArraySome($this->header);
    }

    /**
     * Get all headers, adding typ if necessary
     *
     * @return array
     */
    public function getAllHeaders(): array
    {
        return $this->getHeaders()
                    ->orElse(new ArraySome(['typ' => 'JWT']))
                    ->map(function(array $headers) {
                        if(array_key_exists('typ', $headers)) {
                            return $headers;
                        }
                        $headers['type'] = 'JWT';
                        return $headers;
        })->get();
    }

    /**
     * Get one item from header.
     *
     * @param string $header
     * @return Option
     */
    public function getHeader(string $header): Option
    {
        if(array_key_exists($header, $this->header)) {
            return new Some($this->header[$header]);
        }
        return new None;
    }

    /**
     * Add an item to header.
     *
     * @param string $header
     * @param $value
     * @throws Exception
     */
    public function addHeader(string $header, $value)
    {
        if('typ' == $header && $this->getHeader('typ')->isDefined()) {
            throw new Exception(Exception::CANNOT_CHANGE_TYPE);
        } elseif('alg' == $header) {
            $this->setAlgo($value);
        } else {
            $this->header[$header] = $value;
        }
    }

    /**
     * Add multiple items to header.
     *
     * @param array $headers
     * @throws Exception
     */
    public function addHeaders(array $headers)
    {
        foreach ($headers as $header => $value) {
            $this->addHeader($header, $value);
        }
    }

    /**
     * Remove an item from header.
     *
     * @param string $header
     */
    public function removeHeader(string $header)
    {
        unset($this->header[$header]);
    }

    /**
     * Get all claims.
     *
     * @return ArrayOption
     */
    public function getClaims(): ArrayOption
    {
        if(empty($this->claims)) {
            return new ArrayNone();
        }
        return new ArraySome($this->claims);
    }

    /**
     * Get a single claim.
     *
     * @param string $claim
     * @return Option
     */
    public function getClaim(string $claim): Option
    {
        if(array_key_exists($claim, $this->claims)) {
            return new Some($this->claims[$claim]);
        }
        return new None;
    }

    /**
     * Add an item to the claimset.
     *
     * @param string $claim
     * @param $value
     */
    public function addClaim(string $claim, $value)
    {
        $this->claims[$claim] = $value;
    }

    /**
     * Add multiple items to the claimset.
     *
     * @param array $newClaims
     */
    public function addClaims(array $newClaims)
    {
        foreach ($newClaims as $claim => $value) {
            $this->addClaim($claim, $value);
        }
    }

    /**
     * Remove a claim.
     *
     * @param string $claim
     */
    public function removeClaim(string $claim)
    {
        unset($this->claims[$claim]);
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

    /**
     * Get hashing algorithm.
     *
     * @return StringOption
     */
    public function getAlgo(): StringOption
    {
        return $this->getHeader('alg')
                    ->flatMap(function($value) { return new StringSome($value); })
                    ->orCall(function() { return new StringNone; });
    }

    /**
     * Set hashing algorithm. Must be one of the keys in $this->algos.
     *
     * @param string $algo
     * @throws Exception
     */
    public function setAlgo(string $algo)
    {
        if(!array_key_exists($algo, $this->algos)) {
            throw new Exception(Exception::UNSUPPORTED_ALGO);
        }
        $this->header['alg'] = $algo;
    }

    /**
     * Set secret key.
     *
     * The secret must be a string or a callable that takes this object and returns a string.
     *
     * @param $secret
     */
    public function setSecret($secret)
    {
        if(is_callable($secret)) {
            $this->secret = $secret;
        } else {
            $this->secret = (string) $secret;
        }
    }

    /**
     * Get secret key. If the secret is a callable it will be called at this time.
     *
     * @return StringOption
     */
    public function getSecret(): StringOption
    {
        if(is_callable($this->secret)) {
            $callback = $this->secret;
            $this->setSecret($callback($this));
        }
        if(empty($this->secret)) {
            return new StringNone;
        }
        return new StringSome($this->secret);
    }

    /**
     * Encode JWT.
     *
     * @return string
     * @throws Exception
     */
    public function encode()
    {
        $algo = $this->getAlgo();
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

    /**
     * Validate this JWT object against a JWT token.
     *
     * If no JWT is provided it will use the JWT token used to create this object, if available.
     *
     * @param string $jwt
     * @return bool
     * @throws Exception
     */
    public function isValid(string $jwt = ''): bool
    {
        if(empty($jwt)) {
            $sourceJwt = $this->getSourceJwt();
            if($sourceJwt->isEmpty()) {
                throw new Exception(Exception::VALIDATE_WITHOUT_JWT);
            }
            $jwt = $sourceJwt->get();
        }

        if($this->getHeaders()
                ->filter(function($header) { return count($header) >= 2; })
                ->filter(function($header) { return !empty($header['alg']) && array_key_exists($header['alg'], $this->algos); })
                ->filter(function($header) { return !empty($header['typ']) && $header['typ'] === 'JWT'; })
                ->isEmpty()
        ) {
            return false;
        }

        $now = time();
        if($this->getClaim('exp')->isDefined() && (int) $this->getClaim('exp')->get() <= $now) {
            return false;
        }
        if($this->getClaim('nbf')->isDefined() && (int) $this->getClaim('nbf')->get() >= $now) {
            return false;
        }
        if($this->getClaim('iat')->isDefined() && (int) $this->getClaim('iat')->get() > $now) {
            return false;
        }
        if($this->getClaim('iat')->isDefined() && $this->getClaim('nbf')->isDefined() && (int) $this->getClaim('iat')->get() > (int) $this->getClaim('nbf')->get()) {
            return false;
        }

        foreach($this->validators as $validator) {
            if(!$validator($this)) {
                return false;
            }
        }
        return $jwt === $this->encode();
    }

    /**
     * Add a validator.
     *
     * @param callable $validator
     */
    public function addValidator(callable $validator)
    {
        $this->validators[] = $validator;
    }

    /**
     * Add multiple validators.
     *
     * @param array $validators
     */
    public function addValidators(array $validators)
    {
        foreach($validators as $validator) {
            $this->addValidator($validator);
        }
    }

    /**
     * Get a list of all custom validators.
     *
     * @return array
     */
    public function getValidators(): ArrayOption
    {
        if(empty($this->validators)) {
            return new ArrayNone;
        }
        return new ArraySome($this->validators);
    }
}