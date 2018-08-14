<?php
declare(strict_types=1);
/**
 * Created by IntelliJ IDEA.
 * User: mark
 * Date: 8/13/18
 * Time: 5:03 PM
 */

namespace maarky\Test\Jwt\Option\Generator;

use maarky\Jwt\Option\Generator\Option;
use PHPUnit\Framework\TestCase;
use maarky\Jwt\Generator;

class OptionTest extends TestCase
{
    protected $header = [
        'alg' => 'HS256',
        'typ' => 'JWT'
    ];
    protected $claims = [
        'sub' => 123456
    ];
    protected $secret = 'secret';

    public function getGenerator()
    {
        return new Generator($this->claims, $this->secret, $this->header);
    }

    public function testOption_Some()
    {
        $option = Option::create($this->getGenerator());
        $this->assertTrue($option->isDefined());
    }

    public function testOption_None()
    {
        $this->assertTrue(Option::create(null)->isEmpty());
    }
}
