<?php
declare(strict_types=1);

namespace maarky\Test\Jwt;

use maarky\Jwt\Jwt;
use maarky\Jwt\Exception;

class JwtTest extends \PHPUnit_Framework_TestCase
{
    public function jwtProvider()
    {
        $makeJwt = function ($algo, $claims, $secret)
        {
            $encode = function($input) {
                return str_replace('=', '', strtr(base64_encode($input), '+/', '-_'));
            };
            $algos = [
                'HS256' => 'sha256',
                'HS384' => 'sha384',
                'HS512' => 'sha512',
            ];
            $header = ['alg' => $algo, 'typ' => 'JWT'];
            $headerJson = json_encode($header);
            $claimsJson = json_encode($claims);
            $header64 = $encode($headerJson);
            $claims64 = $encode($claimsJson);
            $jwt = $header64 . '.' . $claims64;
            $signature = hash_hmac($algos[$algo], $jwt, $secret, true);

            return $jwt . '.' . $encode($signature);
        };

        $algos = [
            'HS256',
            'HS384',
            'HS512',
        ];

        $claims = [
            [
                'qwerty' => '1xdcftg',
                'rvrg' => 'efvgrn',
                'qwetbgrvrty' => 'frvf',
                'thnh' => 'ujyhted'
            ],
            [
                'qwerty' => '2xdcftg',
                'rvrg' => 'efvgrn',
                'qwetbgrvrty' => 'frvf',
                'thnh' => 'ujyhted',
                'exp' => time() + 5
            ],
            [
                'qwerty' => '3xdcftg',
                'rvrg' => 'efvgrn',
                'qwetbgrvrty' => 'frvf',
                'thnh' => 'ujyhted',
                'exp' => time() - 5,
                'PASS' => false
            ],
            [
                'qwerty' => '4xdcftg',
                'rvrg' => 'efvgrn',
                'qwetbgrvrty' => 'frvf',
                'thnh' => 'ujyhted',
                'iat' => time() - 5
            ],
            [
                'qwerty' => '5xdcftg',
                'rvrg' => 'efvgrn',
                'qwetbgrvrty' => 'frvf',
                'thnh' => 'ujyhted',
                'iat' => time() + 5,
                'PASS' => false
            ],
            [
                'qwerty' => '6xdcftg',
                'rvrg' => 'efvgrn',
                'qwetbgrvrty' => 'frvf',
                'thnh' => 'ujyhted',
                'nbf' => time() - 5
            ],
            [
                'qwerty' => '7xdcftg',
                'rvrg' => 'efvgrn',
                'qwetbgrvrty' => 'frvf',
                'thnh' => 'ujyhteds',
                'nbf' => time() + 50,
                'PASS' => false
            ],
            [
                'qwerty' => '8xdcftg',
                'rvrg' => 'efvgrn',
                'qwetbgrvrty' => 'frvf',
                'thnh' => 'ujyhted',
                'nbf' => time() - 5,
                'iat' => time() - 10
            ],
            [
                'qwerty' => '9xdcftg',
                'rvrg' => 'efvgrn',
                'qwetbgrvrty' => 'frvf',
                'thnh' => 'ujyhted',
                'nbf' => time() - 10,
                'iat' => time() - 5,
                'PASS' => false
            ]
        ];

        $secrets = [
            'ourbfhjehdv',
            'ughti4uhgvkjfndsk',
            'iurgheruvbddjs'
        ];

        $fixture = [];

        foreach ($algos as $algo) {
            $header = ['alg' => $algo, 'typ' => 'JWT'];
            foreach ($claims as $claim) {
                foreach ($secrets as $secret) {
                    $shouldPass = array_key_exists('PASS', $claim) ? (bool) $claim['PASS'] : true;
                    $fixture[] = [
                        'header' => $header,
                        'claims' => $claim,
                        'secret' => $secret,
                        'jwt' => $makeJwt($algo, $claim, $secret),
                        'pass' => $shouldPass
                    ];
                }
            }
        }
        return $fixture;
    }

    protected function getNewKey(array $array, array $exclude = [])
    {
        $newClaim = 'X';
        while(array_key_exists($newClaim, $array) || array_key_exists($newClaim, $exclude)) {
            $newClaim .= 'X';
        }
        return $newClaim;
    }

    public function testJwt_badHeader_base64()
    {
        $this->setExpectedException('maarky\Jwt\Exception', Exception::CANNOT_DECODE_BASE64);
        $jwt = '&' . $this->jwtProvider()[0]['jwt'];
        new Jwt($jwt);
    }

    public function testJwt_badHeader_json()
    {
        $this->setExpectedException('maarky\Jwt\Exception', Exception::CANNOT_DECODE_JSON);
        $jwt = $this->jwtProvider()[0]['jwt'];
        $parts = explode('.', $jwt);
        $parts[0] = base64_encode('hello');
        $jwt = implode('.', $parts);
        new Jwt($jwt);
    }

    public function testJwt_badClaims_base64()
    {
        $this->setExpectedException('maarky\Jwt\Exception', Exception::CANNOT_DECODE_JSON);
        $jwt = $this->jwtProvider()[0]['jwt'];
        $parts = explode('.', $jwt);
        $parts[1] = 'hello';
        $jwt = implode('.', $parts);
        new Jwt($jwt);
    }

    public function testJwt_badClaims_json()
    {
        $this->setExpectedException('maarky\Jwt\Exception', Exception::CANNOT_DECODE_JSON);
        $jwt = $this->jwtProvider()[0]['jwt'];
        $parts = explode('.', $jwt);
        $parts[1] = base64_encode('hello');
        $jwt = implode('.', $parts);
        new Jwt($jwt);
    }

    public function testJwt_badSecre()
    {
        $this->setExpectedException('maarky\Jwt\Exception', Exception::ENCODE_WITHOUT_SECRET);
        new Jwt([], 1);
    }

    public function testJwt_secretIsSome()
    {
        $jwt = new Jwt([], 'secret');
        $this->assertInstanceOf('maarky\Option\Type\String\Some', $jwt->getSecret());
    }

    public function testJwt_secretIsNone()
    {
        $jwt = new Jwt();
        $this->assertInstanceOf('maarky\Option\Type\String\None', $jwt->getSecret());
    }

    public function testJwt_getSecret_fromJwt_passedSeparately()
    {
        $jwt = $this->jwtProvider()[0]['jwt'];
        $secret = 'secret';
        $jwtObj = new Jwt($jwt, $secret);
        $this->assertEquals($secret, $jwtObj->getSecret()->get());
    }

    public function testJwt_getSourceJwt_fromJwt()
    {
        $jwt = $this->jwtProvider()[0]['jwt'];
        $jwtObj = new Jwt($jwt);
        $this->assertEquals($jwt, $jwtObj->getSourceJwt()->get());
    }

    public function testJwt_getSourceJwt_fromJwt_isSome()
    {
        $jwt = $this->jwtProvider()[0]['jwt'];
        $jwtObj = new Jwt($jwt);
        $this->assertInstanceOf('maarky\Option\Type\String\Some', $jwtObj->getSourceJwt());
    }

    public function testJwt_getSourceJwt_noJwt_isNone()
    {
        $jwtObj = new Jwt();
        $this->assertInstanceOf('maarky\Option\Type\String\None', $jwtObj->getSourceJwt());
    }

    public function testJwt_getSourceJwt_fromJwt_afterAddingClaim()
    {
        $data = $this->jwtProvider()[0];
        $jwt = $data['jwt'];
        $claims = $data['claims'];

        $jwtObj = new Jwt($jwt);
        $newClaim = $this->getNewKey($claims);
        $jwtObj->addClaim($newClaim, 'X');
        $this->assertEquals($jwt, $jwtObj->getSourceJwt()->get());
    }

    public function testJwt_getSourceJwt_fromJwt_afterAddingClaims()
    {
        $data = $this->jwtProvider()[0];
        $jwt = $data['jwt'];
        $claims = $data['claims'];

        $jwtObj = new Jwt($jwt);
        $newClaim1 = $this->getNewKey($claims);
        $newClaim2 = $this->getNewKey($claims, [$newClaim1]);
        $jwtObj->addClaims([$newClaim1 => 'X', $newClaim2 => 'X']);
        $this->assertEquals($jwt, $jwtObj->getSourceJwt()->get());
    }

    public function testJwt_getSourceJwt_fromJwt_afterRemovingClaim()
    {
        $data = $this->jwtProvider()[0];
        $jwt = $data['jwt'];
        $claims = $data['claims'];

        $jwtObj = new Jwt($jwt);
        $removeClaim = key($claims);
        $jwtObj->removeClaim($removeClaim);
        $this->assertEquals($jwt, $jwtObj->getSourceJwt()->get());
    }

    public function testJwt_getSourceJwt_fromJwt_afterAddingHeader()
    {
        $data = $this->jwtProvider()[0];
        $jwt = $data['jwt'];
        $header = $data['header'];

        $jwtObj = new Jwt($jwt);
        $newHeader = $this->getNewKey($header);
        $jwtObj->addHeader($newHeader, 'X');
        $this->assertEquals($jwt, $jwtObj->getSourceJwt()->get());
    }

    public function testJwt_getSourceJwt_fromJwt_afterAddingHeaders()
    {
        $data = $this->jwtProvider()[0];
        $jwt = $data['jwt'];
        $header = $data['header'];

        $jwtObj = new Jwt($jwt);
        $newHeader1 = $this->getNewKey($header);
        $newHeader2 = $this->getNewKey($header, [$newHeader1]);
        $jwtObj->addHeaders([$newHeader1 => 'X', $newHeader2 => 'X']);
        $this->assertEquals($jwt, $jwtObj->getSourceJwt()->get());
    }

    public function testJwt_getSourceJwt_fromJwt_afterRemovingHeader()
    {
        $data = $this->jwtProvider()[0];
        $jwt = $data['jwt'];
        $header = $data['header'];

        $jwtObj = new Jwt($jwt);
        $newHeader = $this->getNewKey($header);
        $jwtObj->addHeader($newHeader, 'X');
        $jwtObj->removeHeader($newHeader);
        $this->assertEquals($jwt, $jwtObj->getSourceJwt()->get());
    }
    public function testJwt_getSourceJwt_noJwtProvided()
    {
        $jwt = new Jwt();
        $this->assertTrue($jwt->getSourceJwt()->isEmpty());
    }

    public function testJwt_getClaims_fromJwt_isSome()
    {
        $data = $this->jwtProvider()[0];
        $jwt = $data['jwt'];

        $jwtObj = new Jwt($jwt);
        $this->assertInstanceOf('maarky\Option\Type\Arr\Some', $jwtObj->getClaims());
    }

    public function testJwt_getClaims_isNone()
    {
        $jwtObj = new Jwt();
        $this->assertInstanceOf('maarky\Option\Type\Arr\None', $jwtObj->getClaims());
    }

    public function testJwt_getClaims_fromJwt()
    {
        $data = $this->jwtProvider()[0];
        $jwt = $data['jwt'];
        $claims = $data['claims'];

        $jwtObj = new Jwt($jwt);
        $this->assertEquals($claims, $jwtObj->getClaims()->get());
    }

    public function testJwt_getClaim_fromJwt()
    {
        $data = $this->jwtProvider()[0];
        $jwt = $data['jwt'];
        $claims = $data['claims'];

        $jwtObj = new Jwt($jwt);
        foreach($claims as $claim => $value) {
            $this->assertEquals($value, $jwtObj->getClaim($claim)->get());
        }
    }

    public function testJwt_getClaim_fromJwt_claimNotSet()
    {
        $data = $this->jwtProvider()[0];
        $jwt = $data['jwt'];
        $claims = $data['claims'];

        $jwtObj = new Jwt($jwt);
        $badClaim = $this->getNewKey($claims);
        $this->assertTrue($jwtObj->getClaim($badClaim)->isEmpty());
    }

    public function testJwt_hasClaim_fromJwt()
    {
        $data = $this->jwtProvider()[0];
        $jwt = $data['jwt'];
        $claims = $data['claims'];

        $jwtObj = new Jwt($jwt);
        foreach($claims as $claim => $value) {
            $this->assertTrue($jwtObj->getClaim($claim)->isDefined());
        }
    }

    public function testJwt_addClaim_getClaim_hasClaim_fromJwt()
    {
        $data = $this->jwtProvider()[0];
        $jwt = $data['jwt'];
        $claims = $data['claims'];

        $jwtObj = new Jwt($jwt);
        foreach($claims as $claim => $value) {
            $newClaim = $claim . rand(0, getrandmax());
            $jwtObj->addClaim($newClaim, $value);
            $this->assertTrue($jwtObj->getClaim($newClaim)->isDefined());
        }
    }

    public function testJwt_addClaim_getClaim_fromJwt()
    {
        $data = $this->jwtProvider()[0];
        $jwt = $data['jwt'];
        $claims = $data['claims'];

        $jwtObj = new Jwt($jwt);
        foreach($claims as $claim => $value) {
            $newClaim = $claim . rand(0, getrandmax());
            $jwtObj->addClaim($newClaim, $value);
            $this->assertEquals($value, $jwtObj->getClaim($newClaim)->get());
        }
    }

    public function testJwt_removeClaim_getClaim_fromJwt()
    {
        $data = $this->jwtProvider()[0];
        $jwt = $data['jwt'];
        $claims = $data['claims'];

        $jwtObj = new Jwt($jwt);
        $removeClaim = key($claims);
        $jwtObj->removeClaim($removeClaim);
        $this->assertTrue($jwtObj->getClaim($removeClaim)->isEmpty());
    }

    public function testJwt_addClaims_getClaims_fromJwt()
    {
        $data = $this->jwtProvider()[0];
        $jwt = $data['jwt'];
        $claims = $data['claims'];

        $jwtObj = new Jwt($jwt);
        $newClaim1 = $this->getNewKey($claims);
        $newClaim2 = $this->getNewKey($claims, [$newClaim1]);
        $claims[$newClaim1] = 'X';
        $claims[$newClaim2] = 'X';
        $jwtObj->addClaims([$newClaim1 => $claims[$newClaim1], $newClaim2 => $claims[$newClaim2]]);
        $this->assertEquals($claims, $jwtObj->getClaims()->get());
    }

    public function testJwt_addClaims_getClaims_fromJwt_noClaimsChange()
    {
        $data = $this->jwtProvider()[0];
        $jwt = $data['jwt'];
        $claims = $data['claims'];

        $jwtObj = new Jwt($jwt);
        $jwtObj->addClaims($claims);
        $this->assertEquals($claims, $jwtObj->getClaims()->get());
    }

    public function testJwt_addClaims_getClaims_fromJwt_allClaimsChange()
    {
        $data = $this->jwtProvider()[0];
        $jwt = $data['jwt'];
        $claims = $data['claims'];

        $jwtObj = new Jwt($jwt);
        foreach ($claims as $claim => $value) {
            $claims[$claim] = $value . 'X';
        }
        $jwtObj->addClaims($claims);
        $this->assertEquals($claims, $jwtObj->getClaims()->get());
    }

    public function testJwt_addClaims_getClaims_fromJwt_allClaimsChange_newClaimsAdded()
    {
        $data = $this->jwtProvider()[0];
        $jwt = $data['jwt'];
        $claims = $data['claims'];

        $jwtObj = new Jwt($jwt);
        foreach ($claims as $claim => $value) {
            $claims[$claim] = $value . 'X';
        }
        $newClaim1 = $this->getNewKey($claims);
        $newClaim2 = $this->getNewKey($claims, [$newClaim1]);
        $claims[$newClaim1] = 'X';
        $claims[$newClaim2] = 'X';
        $jwtObj->addClaims($claims);
        $this->assertEquals($claims, $jwtObj->getClaims()->get());
    }

    public function testJwt_getHeaders_fromJwt_isSome()
    {
        $data = $this->jwtProvider()[0];
        $jwt = $data['jwt'];

        $jwtObj = new Jwt($jwt);
        $this->assertInstanceOf('maarky\Option\Type\Arr\Some', $jwtObj->getHeaders());
    }

    public function testJwt_getHeaders_noneSet_isSome()
    {
        $jwtObj = new Jwt();
        $this->assertInstanceOf('maarky\Option\Type\Arr\Some', $jwtObj->getHeaders());
    }

    public function testJwt_getHeaders_fromJwt()
    {
        $data = $this->jwtProvider()[0];
        $jwt = $data['jwt'];
        $header = $data['header'];

        $jwtObj = new Jwt($jwt);
        $this->assertEquals($header, $jwtObj->getHeaders()->get());
    }

    public function testJwt_getHeader_fromJwt_isSome()
    {
        $data = $this->jwtProvider()[0];
        $jwt = $data['jwt'];
        $header = $data['header'];

        $jwtObj = new Jwt($jwt);
        foreach ($header as $index => $value) {
            $this->assertInstanceOf('maarky\Option\Some', $jwtObj->getHeader($index));
        }
    }

    public function testJwt_getHeader_isNone()
    {
        $jwtObj = new Jwt();
        $this->assertInstanceOf('maarky\Option\None', $jwtObj->getHeader('a'));
    }

    public function testJwt_getHeader_fromJwt()
    {
        $data = $this->jwtProvider()[0];
        $jwt = $data['jwt'];
        $header = $data['header'];

        $jwtObj = new Jwt($jwt);
        foreach ($header as $index => $value) {
            $this->assertEquals($header[$index], $jwtObj->getHeader($index)->get());
        }
    }

    public function testJwt_getHeader_hasHeader_fromJwt()
    {
        $data = $this->jwtProvider()[0];
        $jwt = $data['jwt'];
        $header = $data['header'];

        $jwtObj = new Jwt($jwt);
        foreach ($header as $index => $value) {
            $this->assertTrue($jwtObj->getHeader($index)->isDefined());
        }
    }

    public function testJwt_addHeader_fromJwt_getHeaders()
    {
        $data = $this->jwtProvider()[0];
        $jwt = $data['jwt'];
        $header = $data['header'];

        $jwtObj = new Jwt($jwt);
        $newHeader = $this->getNewKey($header);
        $header[$newHeader] = 'X';
        $jwtObj->addHeader($newHeader, $header[$newHeader]);
        $this->assertEquals($header, $jwtObj->getHeaders()->get());
    }

    public function testJwt_removeHeader_fromJwt_getHeaders()
    {
        $data = $this->jwtProvider()[0];
        $jwt = $data['jwt'];
        $header = $data['header'];

        $jwtObj = new Jwt($jwt);
        $newHeader = $this->getNewKey($header);
        $jwtObj->addHeader($newHeader, 'X');
        $jwtObj->removeHeader($newHeader);
        $this->assertEquals($header, $jwtObj->getHeaders()->get());
    }

    public function testJwt_addHeaders_fromJwt_getHeaders()
    {
        $data = $this->jwtProvider()[0];
        $jwt = $data['jwt'];
        $header = $data['header'];

        $jwtObj = new Jwt($jwt);
        $newHeader1 = $this->getNewKey($header);
        $newHeader2 = $this->getNewKey($header, [$newHeader1]);
        $header[$newHeader1] = 'X';
        $header[$newHeader2] = 'X';
        $jwtObj->addHeaders([$newHeader1 => $header[$newHeader1], $newHeader2 => $header[$newHeader2]]);
        $this->assertEquals($header, $jwtObj->getHeaders()->get());
    }

    public function testJwt_getAlgo_fromJwt_isSome()
    {
        $data = $this->jwtProvider()[0];
        $jwt = $data['jwt'];

        $jwtObj = new Jwt($jwt);
        $this->assertInstanceOf('maarky\Option\Type\String\Some', $jwtObj->getAlgo());
    }

    public function testJwt_getAlgo_isNone()
    {
        $jwtObj = new Jwt();
        $this->assertInstanceOf('maarky\Option\Type\String\None', $jwtObj->getAlgo());
    }

    public function testJwt_getAlgo_fromJwt()
    {
        $data = $this->jwtProvider()[0];
        $jwt = $data['jwt'];
        $header = $data['header'];

        $jwtObj = new Jwt($jwt);
        $this->assertEquals($header['alg'], $jwtObj->getAlgo()->get());
    }

    public function testJwt_setAlgo()
    {
        $jwtObj = new Jwt();
        foreach ($jwtObj->getSupportedAlgos() as $algo) {
            $jwtObj->setAlgo($algo);
            $this->assertEquals($algo, $jwtObj->getAlgo()->get());
        }
    }

    public function testJwt_setAlgo_unsupportedAlgo()
    {
        $this->setExpectedException('maarky\Jwt\Exception', Exception::UNSUPPORTED_ALGO);
        $jwtObj = new Jwt();
        foreach ($jwtObj->getSupportedAlgos() as $algo) {
            $jwtObj->setAlgo($algo . 'XXXXXXXX');
        }
    }

    public function testJwt_setAlgo_fromHeader()
    {
        $jwtObj = new Jwt();
        foreach ($jwtObj->getSupportedAlgos() as $algo) {
            $jwtObj->addHeader('alg', $algo);
            $this->assertEquals($algo, $jwtObj->getAlgo()->get());
        }
    }

    public function testJwt_setAlgo_fromHeader_unsupportedAlgo()
    {
        $this->setExpectedException('maarky\Jwt\Exception', Exception::UNSUPPORTED_ALGO);
        $jwtObj = new Jwt();
        foreach ($jwtObj->getSupportedAlgos() as $algo) {
            $jwtObj->addHeader('alg', $algo . 'XXXXXXXXX');
        }
    }

    public function testHasAlgo()
    {
        $algo = $this->jwtProvider()[0]['header']['alg'];
        $jwtObj = new Jwt();
        $jwtObj->setAlgo($algo);
        $this->assertTrue($jwtObj->getAlgo()->isDefined());
    }

    public function testJwt_canSetType()
    {
        $this->setExpectedException('maarky\Jwt\Exception', Exception::CANNOT_CHANGE_TYPE);
        $jwtObj = new Jwt();
        $jwtObj->addHeader('typ', 'X');
        $jwtObj->addHeader('typ', 'X');
    }

    public function testSetSecret_usingString()
    {
        $jwtObj = new Jwt();
        $jwtObj->setSecret('X');
        $this->assertEquals('X', $jwtObj->getSecret()->get());
    }

    public function testJwt_justClaims()
    {
        $claims = $this->jwtProvider()[0]['claims'];
        $jwtObj = new Jwt(['claims' => $claims]);
        $this->assertEquals($claims, $jwtObj->getClaims()->get());
    }

    public function testJwt_justHeaders()
    {
        $header = $this->jwtProvider()[0]['header'];
        $jwtObj = new Jwt(['header' => $header]);
        $this->assertEquals($header, $jwtObj->getHeaders()->get());
    }

    public function testJwt_justHeaders_ignoresType()
    {
        $header = $this->jwtProvider()[0]['header'];
        $useHeader = $header;
        $useHeader['typ'] = 'XXX';
        $jwtObj = new Jwt(['header' => $header]);
        $this->assertEquals($header, $jwtObj->getHeaders()->get());
    }

    public function testJwt_justAlgo()
    {
        $alg = $this->jwtProvider()[0]['header']['alg'];
        $jwtObj = new Jwt(['algo' => $alg]);
        $this->assertEquals($alg, $jwtObj->getAlgo()->get());
    }

    public function testJwt_doubleAlgo()
    {
        $this->setExpectedException('maarky\Jwt\Exception', Exception::CONSTRUCTOR_WITH_DOUBLE_ALGO);
        $header = $this->jwtProvider()[0]['header'];
        $jwtObj = new Jwt(['header' => $header, 'algo' => $header['alg']]);
        //$this->assertEquals($header, $jwtObj->getHeaders());
    }

    public function testJwt_unsupportedAlgo()
    {
        $this->setExpectedException('maarky\Jwt\Exception', Exception::UNSUPPORTED_ALGO);
        $header = $this->jwtProvider()[0]['header'];
        new Jwt(['algo' => $header['alg'] . 'X']);
    }

    public function testJwt_unsupportedAlgo_asHeader()
    {
        $this->setExpectedException('maarky\Jwt\Exception', Exception::UNSUPPORTED_ALGO);
        $header = $this->jwtProvider()[0]['header'];
        $header['alg'] = 'X';
        new Jwt(['header' => $header]);
    }

    public function test_jwt_withClaims_withHeader_testClaims()
    {
        $data = $this->jwtProvider()[0];
        $jwt = new Jwt(['claims' => $data['claims'], 'header' => $data['header']]);
        $this->assertEquals($data['claims'], $jwt->getClaims()->get());
    }

    public function test_jwt_withClaims_withHeader_testHeader()
    {
        $data = $this->jwtProvider()[0];
        $jwt = new Jwt(['claims' => $data['claims'], 'header' => $data['header']]);
        $this->assertEquals($data['header'], $jwt->getHeaders()->get());
    }

    public function test_jwt_withClaims_withAlgo_testAlg()
    {
        $data = $this->jwtProvider()[0];
        $jwt = new Jwt(['claims' => $data['claims'], 'algo' => $data['header']['alg']]);
        $this->assertEquals($data['header']['alg'], $jwt->getAlgo()->get());
    }

    public function testSecret_provideString()
    {
        $secret = 'secret';
        $jwt = new Jwt();
        $jwt->setSecret($secret);
        $this->assertEquals($secret, $jwt->getSecret()->get());
    }

    public function testSecret_provideCallback()
    {
        $secret = 'secret';
        $callback = function(Jwt $jwt) use($secret) {
            return $secret;
        };
        $jwt = new Jwt();
        $jwt->setSecret($callback);
        $this->assertEquals($secret, $jwt->getSecret()->get());
    }

    public function testSecret_provideCallback_toConstructor()
    {
        $secret = 'secret';
        $callback = function(Jwt $jwt) use($secret) {
            return $secret;
        };
        $jwt = new Jwt([], $callback);
        $this->assertEquals($secret, $jwt->getSecret()->get());
    }

    public function testSecret_provideCallback_toConstructor_secondArg()
    {
        $jwt = $this->jwtProvider()[0]['jwt'];
        $secret = 'secret';
        $callback = function(Jwt $jwt) use($secret) {
            return $secret;
        };
        $jwt = new Jwt($jwt, $callback);
        $this->assertEquals($secret, $jwt->getSecret()->get());
    }

    public function testHasSecret()
    {
        $jwt = new Jwt([], 'secret');
        $this->assertTrue($jwt->getSecret()->isDefined());
    }

    public function testHasSecret_noSecret()
    {
        $jwt = new Jwt();
        $this->assertTrue($jwt->getSecret()->isEmpty());
    }

    public function testEncode_noAlg()
    {
        $this->setExpectedException('maarky\Jwt\Exception', Exception::ENCODE_WITHOUT_ALG);
        $claims = $this->jwtProvider()[0]['claims'];
        $jwt = new Jwt(['claims' => $claims]);
        $jwt->encode();
    }

    public function testEncode_noClaims()
    {
        $this->setExpectedException('maarky\Jwt\Exception', Exception::ENCODE_WITHOUT_CLAIMS);
        $algo = $this->jwtProvider()[0]['header']['alg'];
        $jwt = new Jwt(['algo' => $algo]);
        $jwt->encode();
    }

    public function testEncode_noSecret()
    {
        $this->setExpectedException('maarky\Jwt\Exception', Exception::ENCODE_WITHOUT_SECRET);
        $jwt = $this->jwtProvider()[0]['jwt'];
        $jwt = new Jwt($jwt);
        $jwt->encode();
    }

    /**
     * @dataProvider jwtProvider
     */
    public function testEncode($header, $claims, $secret, $jwt, $pass)
    {
        $jwtObj = new Jwt($jwt, $secret);
        $this->assertEquals($jwt, $jwtObj->encode());
    }

    /**
     * @dataProvider jwtProvider
     */
    public function testValidate_withJwt($header, $claims, $secret, $jwt, $pass)
    {
        $jwtObj = new Jwt($jwt, $secret);
        if($pass) {
            $valid = $jwtObj->isValid();
            $this->assertTrue($valid);
        } else {
            $valid = $jwtObj->isValid();
            $this->assertFalse($valid);
        }
    }

    /**
     * @dataProvider jwtProvider
     */
    public function testValidate_withJwt_withSecretAsCallback($header, $claims, $secret, $jwt, $pass)
    {
        $jwtObj = new Jwt($jwt, function() use($secret) { return $secret; });
        if($pass) {
            $valid = $jwtObj->isValid();
            $this->assertTrue($valid);
        } else {
            $valid = $jwtObj->isValid();
            $this->assertFalse($valid);
        }
    }

    /**
     * @dataProvider jwtProvider
     */
    public function testValidate_withoutJwt($header, $claims, $secret, $jwt, $pass)
    {
        $jwtObj = new Jwt(['header' => $header, 'claims' => $claims], $secret);
        $valid = $jwtObj->isValid($jwt);
        if($pass) {
            $this->assertTrue($valid);
        } else {
            $this->assertFalse($valid);
        }
    }

    public function testAddValidator_oneValidator()
    {
        $jwt = $this->jwtProvider()[0]['jwt'];
        $jwt = new Jwt($jwt);
        $validator = function() { return true; };
        $jwt->addValidator($validator);
        $this->assertEquals([$validator], $jwt->getValidators()->get());
    }

    public function testAddValidator_twoValidators()
    {
        $jwt = $this->jwtProvider()[0];
        $jwt = new Jwt($jwt['jwt'], $jwt['secret']);
        $validator1 = function() { return true; };
        $validator2 = function() { return false; };
        $jwt->addValidator($validator1);
        $jwt->addValidator($validator2);
        $this->assertEquals([$validator1, $validator2], $jwt->getValidators()->get());
    }

    public function testAddValidators_twoValidators()
    {
        $jwt = $this->jwtProvider()[0]['jwt'];
        $jwt = new Jwt($jwt);
        $validators = [
            function() { return true; },
            function() { return false; }
        ];
        $jwt->addValidators($validators);
        $this->assertEquals($validators, $jwt->getValidators()->get());
    }

    public function testValidate_withCustomValidator_valid()
    {
        $jwt = $this->jwtProvider()[0];
        $jwt = new Jwt($jwt['jwt'], $jwt['secret']);
        $validator = function() { return true; };
        $jwt->addValidator($validator);
        $this->assertTrue($jwt->isValid());
    }

    public function testValidate_withCustomValidator_invalid()
    {
        $jwt = $this->jwtProvider()[0];
        $jwt = new Jwt($jwt['jwt'], $jwt['secret']);
        $validator = function(Jwt $jwt) {
            return 'HS256' != $jwt->getAlgo()->getOrElse('');
        };
        $jwt->addValidator($validator);
        $this->assertFalse($jwt->isValid());
    }
}
