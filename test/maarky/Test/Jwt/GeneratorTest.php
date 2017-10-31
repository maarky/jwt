<?php

namespace maarky\Test\Jwt;

use PHPUnit\Framework\TestCase;
use Doctrine\Instantiator\Exception\InvalidArgumentException;
use maarky\Jwt\Generator;

class GeneratorTest extends TestCase
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
        $jwt = new Generator($this->claims, $this->secret, $this->header);
        $this->assertInstanceOf('maarky\Jwt\Generator', $jwt);
    }

    public function testConstruct_empty()
    {
        $jwt = new Generator();
        $this->assertInstanceOf('maarky\Jwt\Generator', $jwt);
    }

    public function testConstruct_onlyHeader()
    {
        $jwt = new Generator(['a' => 1]);
        $this->assertInstanceOf('maarky\Jwt\Generator', $jwt);
    }

    public function testConstruct_onlyClaims()
    {
        $jwt = new Generator(['a' => 1]);
        $this->assertInstanceOf('maarky\Jwt\Generator', $jwt);
    }

    public function testConstruct_onlySecret()
    {
        $jwt = new Generator([], 'a');
        $this->assertInstanceOf('maarky\Jwt\Generator', $jwt);
    }

    public function testConstruct_noSecret()
    {
        $jwt = new Generator($this->claims, null, $this->header);
        $this->assertInstanceOf('maarky\Jwt\Generator', $jwt);
    }

    public function testConstruct_badSecret()
    {
        $this->expectException('TypeError');
        new Generator($this->header, $this->claims, 1);
    }

    public function testConstruct_secretIsCallable()
    {
        $jwt = new Generator($this->claims, function() {}, $this->header);
        $this->assertInstanceOf('maarky\Jwt\Generator', $jwt);
    }

    public function testConstruct_notTrusted()
    {
        $jwt = new Generator($this->claims, function() {}, $this->header);
        $this->assertFalse($jwt->isTrusted());
    }

    public function testConstruct_empty_hasTyp()
    {
        $jwt = new Generator();
        $this->assertSame('JWT', $jwt->getHeader('typ')->get());
    }

    public function testAddHeader()
    {
        $jwt = new Generator($this->claims, $this->secret, $this->header);
        $jwt->addHeader('a', 1);
        $this->assertEquals(1, $jwt->getHeader('a')->get());
    }

    public function testRemoveHeader()
    {
        $jwt = new Generator($this->claims, $this->secret, $this->header);
        $jwt->removeHeader('alg');
        $this->assertTrue($jwt->getHeader('alg')->isEmpty());
    }

    public function testAddClaim()
    {
        $jwt = new Generator($this->claims, $this->secret, $this->header);
        $jwt->addClaim('a', 1);
        $this->assertEquals(1, $jwt->getClaim('a')->get());
    }

    public function testRemoveClaim()
    {
        $jwt = new Generator($this->claims, $this->secret, $this->header);
        $jwt->removeClaim('sub');
        $this->assertTrue($jwt->getClaim('sub')->isEmpty());
    }

    public function testEncode()
    {
        $jwt = new Generator($this->claims, $this->secret, $this->header);
        $this->assertEquals($this->srcJwt, $jwt->encode());
    }

    public function testIsValid()
    {
        $jwt = new Generator($this->claims, $this->secret, $this->header);
        $this->assertTrue($jwt->isValid());
    }

    public function testSetAlg()
    {
        $jwt = new Generator($this->claims, $this->secret, $this->header);
        $jwt->setAlg('HS512');
        $this->assertEquals('HS512', $jwt->getHeader('alg')->get());
    }
}