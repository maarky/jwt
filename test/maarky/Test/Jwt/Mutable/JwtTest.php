<?php

namespace maarky\Test\Jwt\Mutable;

use Doctrine\Instantiator\Exception\InvalidArgumentException;
use maarky\Jwt\Mutable\Jwt;
use maarky\Jwt\Immutable\Jwt as ImmutableJwt;

class JwtTest extends \PHPUnit_Framework_TestCase
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
        new Jwt($this->header, $this->claims, $this->secret);
    }

    public function testConstruct_empty()
    {
        new Jwt();
    }

    public function testConstruct_onlyHeader()
    {
        new Jwt(['a' => 1]);
    }

    public function testConstruct_onlyClaims()
    {
        new Jwt([], ['a' => 1]);
    }

    public function testConstruct_onlySecret()
    {
        new Jwt([], [], 'a');
    }

    public function testConstruct_noSecret()
    {
        new Jwt($this->header, $this->claims);
    }

    public function testConstruct_badSecret()
    {
        $this->expectException('TypeError');
        new Jwt($this->header, $this->claims, 1);
    }

    public function testConstruct_secretIsCallable()
    {
        new Jwt($this->header, $this->claims, function() {});
    }

    public function testConstruct_notTrusted()
    {
        $jwt = new Jwt($this->header, $this->claims, function() {});
        $this->assertFalse($jwt->isTrusted());
    }

    public function testConstruct_empty_hasTyp()
    {
        $jwt = new Jwt();
        $this->assertSame('JWT', $jwt->getHeader('typ')->get());
    }

    public function testAddHeader()
    {
        $jwt = new Jwt($this->header, $this->claims, $this->secret);
        $jwt->addHeader('a', 1);
        $this->assertEquals(1, $jwt->getHeader('a')->get());
    }

    public function testRemoveHeader()
    {
        $jwt = new Jwt($this->header, $this->claims, $this->secret);
        $jwt->removeHeader('alg');
        $this->assertTrue($jwt->getHeader('alg')->isEmpty());
    }

    public function testAddHeaders_noneAtConsruct()
    {
        $jwt = new Jwt([], $this->claims, $this->secret);
        $headers = [
            'a' => 1,
            'typ' => 'JWT'
        ];
        $jwt->addHeaders($headers);
        $this->assertSame($headers, $jwt->getHeaders()->get());
    }

    public function testAddHeaders()
    {
        $jwt = new Jwt($this->header, $this->claims, $this->secret);
        $headers = [
            'a' => 1,
            'b' => 2
        ];
        $jwt->addHeaders($headers);
        $this->assertEquals(array_merge($this->header, $headers), $jwt->getHeaders()->get());
    }

    public function testAddClaim()
    {
        $jwt = new Jwt($this->header, $this->claims, $this->secret);
        $jwt->addClaim('a', 1);
        $this->assertEquals(1, $jwt->getClaim('a')->get());
    }

    public function testAddClaims()
    {
        $jwt = new Jwt($this->header, $this->claims, $this->secret);
        $claims = [
            'a' => 1,
            'b' => 2
        ];
        $jwt->addClaims($claims);
        $this->assertEquals(array_merge($this->claims, $claims), $jwt->getClaims()->get());
    }

    public function testRemoveClaim()
    {
        $jwt = new Jwt($this->header, $this->claims, $this->secret);
        $jwt->removeClaim('sub');
        $this->assertTrue($jwt->getClaim('sub')->isEmpty());
    }

    public function testGetMutable()
    {
        $jwt = new Jwt($this->header, $this->claims, $this->secret);
        $this->assertSame($jwt, $jwt->getMutable());
    }

    public function testEncode()
    {
        $jwt = new Jwt($this->header, $this->claims, $this->secret);
        $this->assertEquals($this->srcJwt, $jwt->encode());
    }

    public function testGetImmutable()
    {
        $jwt = new Jwt($this->header, $this->claims, $this->secret);
        $this->assertInstanceOf('maarky\Jwt\Immutable\Jwt', $jwt->getImmutable());
    }

    public function testGetImmutable_notTrusted()
    {
        $jwt = new Jwt($this->header, $this->claims, $this->secret);
        $this->assertFalse($jwt->getImmutable()->isTrusted());
    }

    public function testIsValid()
    {
        $jwt = new Jwt($this->header, $this->claims, $this->secret);
        $this->assertTrue($jwt->isValid());
    }

    public function testIsValid_badType()
    {
        $jwt = new Jwt($this->header, $this->claims, $this->secret);
        $jwt->setType('xxx');
        $this->assertFalse($jwt->isValid());
    }

    public function testIsValid_badAlgo()
    {
        $jwt = new Jwt($this->header, $this->claims, $this->secret);
        $jwt->setAlgo('xxx');
        $this->assertFalse($jwt->isValid());
    }

    public function testSetAlgo()
    {
        $jwt = new Jwt($this->header, $this->claims, $this->secret);
        $jwt->setAlgo('HS512');
        $this->assertEquals('HS512', $jwt->getHeader('alg')->get());
    }

    public function testSetAlgo_getInRightOrder()
    {
        $jwt = new Jwt($this->header, $this->claims, $this->secret);
        $alg = 'HS512';
        $jwt->setAlgo($alg);
        $expected = $this->header;
        unset($expected['alg']);
        $expected['alg'] = $alg;
        $this->assertTrue($expected === $jwt->getHeaders()->get());
    }

    public function testSetType_getInRightOrder()
    {
        $jwt = new Jwt($this->header, $this->claims, $this->secret);
        $type = 'jwt';
        $jwt->setType($type);
        $expected = $this->header;
        unset($expected['typ']);
        $expected['typ'] = $type;
        $this->assertTrue($expected === $jwt->getHeaders()->get());
    }

    public function testSetType_upper()
    {
        $jwt = new Jwt($this->header, $this->claims, $this->secret);
        $jwt->setType('JWT');
        $this->assertEquals('JWT', $jwt->getHeader('typ')->get());
    }

    public function testSetType_lower()
    {
        $jwt = new Jwt($this->header, $this->claims, $this->secret);
        $jwt->setType('jwt');
        $this->assertEquals('jwt', $jwt->getHeader('typ')->get());
    }
}