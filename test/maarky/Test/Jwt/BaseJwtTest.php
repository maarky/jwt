<?php


namespace maarky\Test\Jwt;

use PHPUnit\Framework\TestCase;
use maarky\Jwt\BaseJwt;
use maarky\Option\Some;
use maarky\Option\None;

class BaseJwtTest extends TestCase
{
    protected $header = [
        'alg' => 'HS256',
        'typ' => 'JWT'
    ];
    protected $claims = [
        'sub' => 123456
    ];
    protected $secret = 'secret';

    protected function getJwt(array $header = null, array $claims = null, $secret = null)
    {
        $header = is_null($header) ? $this->header : $header;
        $claims = is_null($claims) ? $this->claims : $claims;
        if(false === $secret) {
            $secret = null;
        } else {
            $secret = is_string($secret) || is_callable($secret) ? $secret : $this->secret;
        }
        return new class($header, $claims, $secret) extends BaseJwt {
            public function __construct(array $header, array $claims, $secret)
            {
                $this->header = $header;
                $this->claims = $claims;
                $this->secret = $secret;
            }

            public function encode(): string
            {
                return '';
            }
        };
    }

    public function testIsValid()
    {
        $jwt = $this->getJwt();
        $this->assertTrue($jwt->isValid());
    }

    public function testIsValid_badType()
    {
        $headers = $this->header;
        $headers['typ'] = 'xxx';
        $jwt = $this->getJwt($headers);
        $this->assertFalse($jwt->isValid());
    }

    public function testIsValid_badAlgo()
    {
        $headers = $this->header;
        $headers['alg'] = 'xxx';
        $jwt = $this->getJwt($headers);
        $this->assertFalse($jwt->isValid());
    }

    public function testGetHeader_isSome()
    {
        $jwt = $this->getJwt();
        foreach ($this->header as $header => $value) {
            $this->assertTrue($jwt->getHeader($header) instanceof Some);
        }
    }

    public function testGetHeader_isNone()
    {
        $jwt = $this->getJwt();
        foreach ($this->header as $header => $value) {
            $this->assertTrue($jwt->getHeader($header . $value) instanceof None);
        }
    }

    public function testGetHeader_isValue()
    {
        $jwt = $this->getJwt();
        foreach ($this->header as $header => $value) {
            $this->assertEquals($value, $jwt->getHeader($header)->get());
        }
    }

    public function testGetHeaders()
    {
        $jwt = $this->getJwt();
        $this->assertEquals($this->header, $jwt->getHeaders());
    }

    public function testGetClaim_isSome()
    {
        $jwt = $this->getJwt();
        foreach ($this->claims as $claim => $value) {
            $this->assertTrue($jwt->getClaim($claim) instanceof Some);
        }
    }

    public function testGetClaim_isNone()
    {
        $jwt = $this->getJwt();
        foreach ($this->claims as $claim => $value) {
            $this->assertTrue($jwt->getClaim($claim . $value) instanceof None);
        }
    }

    public function testGetClaim_isValue()
    {
        $jwt = $this->getJwt();
        foreach ($this->claims as $claim => $value) {
            $this->assertEquals($value, $jwt->getClaim($claim)->get());
        }
    }

    public function testGetClaims()
    {
        $jwt = $this->getJwt();
        $this->assertEquals($this->claims, $jwt->getClaims());
    }

    public function testGetSecret_isSome()
    {
        $jwt = $this->getJwt();
        $this->assertInstanceOf('maarky\Option\Type\String\Some', $jwt->getSecret());
    }

    public function testGetSecret_isNone()
    {
        $jwt = $this->getJwt(null, null, false);
        $this->assertInstanceOf('maarky\Option\Type\String\None', $jwt->getSecret());
    }

    public function testGetSecret_string()
    {
        $jwt = $this->getJwt();
        $this->assertEquals($this->secret, $jwt->getSecret()->get());
    }

    public function testGetSecret_callable()
    {
        $jwt = $this->getJwt();
        $this->assertEquals($this->secret, $jwt->getSecret()->get());
    }

    public function testGetSecret_callableReceivesJwt()
    {
        $jwt = $this->getJwt(null, null, function($jwt = null) {
            $this->assertInstanceOf('maarky\Jwt\Jwt', $jwt);
            return $this->secret;
        });
        $jwt->getSecret();
    }

    public function testGetValidator_hasDefaults()
    {
        $jwt = $this->getJwt();
        $this->assertNotEmpty($jwt->getValidators());
    }

    public function testGetValidator_clearValidators_hasSome()
    {
        $jwt = $this->getJwt();
        $jwt->clearValidators();
        $this->assertEmpty($jwt->getValidators());
    }

    public function testAddValidator_isSome()
    {
        $jwt = $this->getJwt();
        $validator = function() {};
        $jwt->addValidator('test', $validator);
        $this->assertTrue($jwt->getValidator('test')->isDefined());
    }

    public function testIsValid_false_expired()
    {
        $jwt = $this->getJwt(null, array_merge($this->claims, ['exp' => time() - 1]));
        $this->assertFalse($jwt->isValid());
    }

    public function testIsValid_false_nbf()
    {
        $jwt = $this->getJwt(null, array_merge($this->claims, ['nbf' => time() + 1]));
        $this->assertFalse($jwt->isValid());
    }

    public function testIsValid_false_iat()
    {
        $jwt = $this->getJwt(null, array_merge($this->claims, ['iat' => time() + 1]));
        $this->assertFalse($jwt->isValid());
    }

    public function testIsValid_false_customValidator()
    {
        $jwt = $this->getJwt();
        $jwt->addValidator('test', function() {return false;});
        $this->assertFalse($jwt->isValid());
    }

    public function testIsValid_true_customValidator()
    {
        $jwt = $this->getJwt();
        $jwt->addValidator('test', function() {return true;});
        $this->assertTrue($jwt->isValid());
    }
}
