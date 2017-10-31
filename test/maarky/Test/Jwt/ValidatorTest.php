<?php
declare(strict_types=1);

namespace maarky\Test\Jwt;

use PHPUnit\Framework\TestCase;
use maarky\Jwt\Validator;

class ValidatorTest extends TestCase
{
    protected $srcJwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOjEyMzQ1Nn0.iJGpiQ7KAWGnbAkmKchWn99ZGjQX7kY0PwgwP_u9Jbw';
    protected $header = [
        'alg' => 'HS256',
        'typ' => 'JWT'
    ];
    protected $claims = [
        'sub' => 123456
    ];
    protected $secret = 'secret';

    public function testConstruct()
    {
        $jwt = new Validator($this->srcJwt, $this->secret);
        $this->assertInstanceOf('maarky\Jwt\Validator', $jwt);
    }

    public function testConstruct_noSecret()
    {
        $jwt = new Validator($this->srcJwt);
        $this->assertInstanceOf('maarky\Jwt\Validator', $jwt);
    }

    public function testConstruct_badSecret()
    {
        $this->expectException('TypeError');
        new Validator($this->srcJwt, 1);
    }

    public function testConstruct_secretIsCallable()
    {
        $jwt = new Validator($this->srcJwt, function() {});
        $this->assertInstanceOf('maarky\Jwt\Validator', $jwt);
    }

    public function testIsValid_false_badSecret()
    {
        $jwt = new Validator($this->srcJwt, $this->secret . 'x');
        $this->assertFalse($jwt->isValid());
    }

    public function testGetGenerator()
    {
        $jwt = new Validator($this->srcJwt, $this->secret);
        $this->assertInstanceOf('maarky\Jwt\Generator', $jwt->getGenerator());
    }

    public function testGetGenerator_headers()
    {
        $jwt = new Validator($this->srcJwt, $this->secret);
        $generator = $jwt->getGenerator();
        $this->assertEquals($this->header, $generator->getHeaders());
    }

    public function testGetGenerator_claims()
    {
        $jwt = new Validator($this->srcJwt, $this->secret);
        $generator = $jwt->getGenerator();
        $this->assertEquals($this->claims, $generator->getClaims());
    }

    public function testGetGenerator_secret()
    {
        $jwt = new Validator($this->srcJwt, $this->secret);
        $generator = $jwt->getGenerator();
        $this->assertEquals($this->secret, $generator->getSecret()->get());
    }

    public function testGetGenerator_validators()
    {
        $jwt = new Validator($this->srcJwt, $this->secret);
        $jwt->addValidator('true', function() { return true; });
        $jwt->addValidator('false', function() { return false; });
        $generator = $jwt->getGenerator();
        $this->assertEquals($jwt->getValidators(), $generator->getValidators());
    }
}