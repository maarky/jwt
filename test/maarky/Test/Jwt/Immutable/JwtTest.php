<?php
declare(strict_types=1);

namespace maarky\Test\Jwt\Immutable;

use maarky\Jwt\Immutable\Jwt;
use maarky\Jwt\Mutable\Jwt as MutableJwt;
use maarky\Option\Some;
use maarky\Option\None;
use maarky\Option\Type\String\Some as StringSome;
use maarky\Option\Type\String\None as StringNone;
use maarky\Option\Type\Arr\Some as ArraySome;
use maarky\Option\Type\Arr\None as ArrayNone;

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
        new Jwt($this->srcJwt, $this->secret);
    }

    public function testConstruct_noSecret()
    {
        new Jwt($this->srcJwt);
    }

    public function testConstruct_badSecret()
    {
        $this->expectException('TypeError');
        new Jwt($this->srcJwt, 1);
    }

    public function testConstruct_secretIsCallable()
    {
        new Jwt($this->srcJwt, function() {});
    }

    public function testConstruct_trusted()
    {
        $jwt = new Jwt($this->srcJwt);
        $this->assertTrue($jwt->isTrusted());
    }

    public function testGetHeader_isSome()
    {
        $jwt = new Jwt($this->srcJwt);
        foreach ($this->header as $header => $value) {
            $this->assertTrue($jwt->getHeader($header) instanceof Some);
        }
    }

    public function testGetHeader_isNone()
    {
        $jwt = new Jwt($this->srcJwt);
        foreach ($this->header as $header => $value) {
            $this->assertTrue($jwt->getHeader($header . $value) instanceof None);
        }
    }

    public function testGetHeader_isValue()
    {
        $jwt = new Jwt($this->srcJwt);
        foreach ($this->header as $header => $value) {
            $this->assertEquals($value, $jwt->getHeader($header)->get());
        }
    }

    public function testGetHeaders()
    {
        $jwt = new Jwt($this->srcJwt);
        $this->assertEquals($this->header, $jwt->getHeaders()->get());
    }

    public function testGetClaim_isSome()
    {
        $jwt = new Jwt($this->srcJwt);
        foreach ($this->claims as $claim => $value) {
            $this->assertTrue($jwt->getClaim($claim) instanceof Some);
        }
    }

    public function testGetClaim_isNone()
    {
        $jwt = new Jwt($this->srcJwt);
        foreach ($this->claims as $claim => $value) {
            $this->assertTrue($jwt->getClaim($claim . $value) instanceof None);
        }
    }

    public function testGetClaim_isValue()
    {
        $jwt = new Jwt($this->srcJwt);
        foreach ($this->claims as $claim => $value) {
            $this->assertEquals($value, $jwt->getClaim($claim)->get());
        }
    }

    public function testGetClaims()
    {
        $jwt = new Jwt($this->srcJwt);
        $this->assertEquals($this->claims, $jwt->getClaims()->get());
    }

    public function testEncode()
    {
        $jwt = new Jwt($this->srcJwt);
        $this->assertEquals($this->srcJwt, $jwt->encode());
    }

    public function testGetSecret_isSome()
    {
        $jwt = new Jwt($this->srcJwt, $this->secret);
        $this->assertInstanceOf('maarky\Option\Type\String\Some', $jwt->getSecret());
    }

    public function testGetSecret_isNone()
    {
        $jwt = new Jwt($this->srcJwt);
        $this->assertInstanceOf('maarky\Option\Type\String\None', $jwt->getSecret());
    }

    public function testGetSecret_string()
    {
        $jwt = new Jwt($this->srcJwt, $this->secret);
        $this->assertEquals($this->secret, $jwt->getSecret()->get());
    }

    public function testGetSecret_callable()
    {
        $jwt = new Jwt($this->srcJwt, function() { return $this->secret; });
        $this->assertEquals($this->secret, $jwt->getSecret()->get());
    }

    public function testGetSecret_callableReceivesJwt()
    {
        $jwt = new Jwt($this->srcJwt, function(Jwt $jwt) {
            $this->assertNotEmpty($jwt);
        });
        $jwt->getSecret();
    }

    public function testAddValidator_isNone()
    {
        $jwt = new Jwt($this->srcJwt);
        $this->assertInstanceOf('maarky\Option\Type\Arr\None', $jwt->getValidators());
    }

    public function testAddValidator_isSome()
    {
        $jwt = new Jwt($this->srcJwt);
        $validator = function() {};
        $jwt->addValidator($validator);
        $this->assertInstanceOf('maarky\Option\Type\Arr\Some', $jwt->getValidators());
    }

    public function testAddValidator()
    {
        $jwt = new Jwt($this->srcJwt);
        $validator = function() {};
        $jwt->addValidator($validator);
        $this->assertEquals([$validator], $jwt->getValidators()->get());
    }

    public function testAddValidator_many()
    {
        $jwt = new Jwt($this->srcJwt);
        $validators = [function() {}, function() {}];
        $jwt->addValidator(...$validators);
        $this->assertEquals($validators, $jwt->getValidators()->get());
    }

    public function testIsValid()
    {
        $jwt = new Jwt($this->srcJwt, $this->secret);
        $this->assertTrue($jwt->isValid());
    }

    public function testIsValid_false_expired()
    {
        $mutableJwt = new MutableJwt($this->header, $this->claims, $this->secret);
        $mutableJwt->addClaim('exp', time() - 1);
        $jwt = new Jwt($mutableJwt->encode(), $this->secret);
        $this->assertFalse($jwt->isValid());
    }

    public function testIsValid_false_nbf()
    {
        $mutableJwt = new MutableJwt($this->header, $this->claims, $this->secret);
        $mutableJwt->addClaim('nbf', time() + 1);
        $jwt = new Jwt($mutableJwt->encode(), $this->secret);
        $this->assertFalse($jwt->isValid());
    }

    public function testIsValid_false_iat()
    {
        $mutableJwt = new MutableJwt($this->header, $this->claims, $this->secret);
        $mutableJwt->addClaim('iat', time() + 1);
        $jwt = new Jwt($mutableJwt->encode(), $this->secret);
        $this->assertFalse($jwt->isValid());
    }

    public function testIsValid_false_iatAndNbf()
    {
        $mutableJwt = new MutableJwt($this->header, $this->claims, $this->secret);
        $mutableJwt->addClaim('iat', time() - 1);
        $mutableJwt->addClaim('nbf', time() - 2);
        $jwt = new Jwt($mutableJwt->encode(), $this->secret);
        $this->assertFalse($jwt->isValid());
    }

    public function testIsValid_false_customValidator()
    {
        $mutableJwt = new MutableJwt($this->header, $this->claims, $this->secret);
        $jwt = new Jwt($mutableJwt->encode(), $this->secret);
        $jwt->addValidator(function() {return false;});
        $this->assertFalse($jwt->isValid());
    }

    public function testIsValid_true_customValidator()
    {
        $mutableJwt = new MutableJwt($this->header, $this->claims, $this->secret);
        $jwt = new Jwt($mutableJwt->encode(), $this->secret);
        $jwt->addValidator(function() {return true;});
        $this->assertTrue($jwt->isValid());
    }

    public function testIsValid_false_badSecret()
    {
        $jwt = new Jwt($this->srcJwt, $this->secret . 'x');
        $this->assertFalse($jwt->isValid());
    }

    public function testGetMutable()
    {
        $jwt = new Jwt($this->srcJwt, $this->secret);
        $this->assertInstanceOf('maarky\Jwt\Mutable\Jwt', $jwt->getMutable());
    }

    public function testGetMutable_headers()
    {
        $jwt = new Jwt($this->srcJwt, $this->secret);
        $mutable = $jwt->getMutable();
        $this->assertEquals($this->header, $mutable->getHeaders()->get());
    }

    public function testGetMutable_claims()
    {
        $jwt = new Jwt($this->srcJwt, $this->secret);
        $mutable = $jwt->getMutable();
        $this->assertEquals($this->claims, $mutable->getClaims()->get());
    }

    public function testGetMutable_secret()
    {
        $jwt = new Jwt($this->srcJwt, $this->secret);
        $mutable = $jwt->getMutable();
        $this->assertEquals($this->secret, $mutable->getSecret()->get());
    }

    public function testGetMutable_validators()
    {
        $jwt = new Jwt($this->srcJwt, $this->secret);
        $validators = [
            function() { return true; },
            function() { return false; }
        ];
        $jwt->addValidator(...$validators);
        $mutable = $jwt->getMutable();
        $this->assertEquals($validators, $mutable->getValidators()->get());
    }

    public function testAddHeader()
    {
        $jwt = new Jwt($this->srcJwt, $this->secret);
        $this->assertInstanceOf('maarky\Jwt\Mutable\Jwt', $jwt->addHeader('a', 1));
    }

    public function testAddHeader_testHeader()
    {
        $jwt = new Jwt($this->srcJwt, $this->secret);
        $newHeader = [
            'a' => 1
        ];
        $expectedHeader = array_merge($this->header, $newHeader);
        $this->assertEquals($expectedHeader, $jwt->addHeader(key($newHeader), current($newHeader))->getHeaders()->get());
    }

    public function testAddHeaders()
    {
        $jwt = new Jwt($this->srcJwt, $this->secret);
        $newHeader = [
            'a' => 1,
            'b' => 2
        ];
        $this->assertInstanceOf('maarky\Jwt\Mutable\Jwt', $jwt->addHeaders($newHeader));
    }

    public function testAddHeaders_testHeader()
    {
        $jwt = new Jwt($this->srcJwt, $this->secret);
        $newHeader = [
            'a' => 1,
            'b' => 2
        ];
        $expectedHeader = array_merge($this->header, $newHeader);
        $this->assertEquals($expectedHeader, $jwt->addHeaders($newHeader)->getHeaders()->get());
    }

    public function testAddClaim()
    {
        $jwt = new Jwt($this->srcJwt, $this->secret);
        $this->assertInstanceOf('maarky\Jwt\Mutable\Jwt', $jwt->addClaim('a', 1));
    }

    public function testAddClaim_testClaims()
    {
        $jwt = new Jwt($this->srcJwt, $this->secret);
        $newClaims = [
            'a' => 1
        ];
        $expectedClaims = array_merge($this->claims, $newClaims);
        $this->assertEquals($expectedClaims, $jwt->addClaim(key($newClaims), current($newClaims))->getClaims()->get());
    }

    public function testAddClaims()
    {
        $jwt = new Jwt($this->srcJwt, $this->secret);
        $newClaims = [
            'a' => 1,
            'b' => 2
        ];
        $this->assertInstanceOf('maarky\Jwt\Mutable\Jwt', $jwt->addClaims($newClaims));
    }

    public function testAddClaims_testClaims()
    {
        $jwt = new Jwt($this->srcJwt, $this->secret);
        $newClaims = [
            'a' => 1,
            'b' => 2
        ];
        $expectedClaims = array_merge($this->claims, $newClaims);
        $this->assertEquals($expectedClaims, $jwt->addClaims($newClaims)->getClaims()->get());
    }

    public function testSetAlgo_isMutable()
    {
        $jwt = new Jwt($this->srcJwt, $this->secret);
        $this->assertInstanceOf('maarky\Jwt\Mutable\Jwt', $jwt->setAlgo('HS512'));
    }

    public function testSetAlgo_testAlgo()
    {
        $jwt = new Jwt($this->srcJwt, $this->secret);
        $this->assertEquals('HS512', $jwt->setAlgo('HS512')->getHeader('alg')->get());
    }

    public function testSetType_isMutable()
    {
        $jwt = new Jwt($this->srcJwt, $this->secret);
        $this->assertInstanceOf('maarky\Jwt\Mutable\Jwt', $jwt->setType('jwt'));
    }

    public function testSetType_testType()
    {
        $jwt = new Jwt($this->srcJwt, $this->secret);
        $this->assertEquals('XXX', $jwt->setType('XXX')->getHeader('typ')->get());
    }
}