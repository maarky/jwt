<?php
declare(strict_types=1);
/**
 * Created by IntelliJ IDEA.
 * User: mark
 * Date: 8/13/18
 * Time: 5:03 PM
 */

namespace maarky\Test\Jwt\Option\Validator;

use maarky\Jwt\Option\Validator\Option;
use PHPUnit\Framework\TestCase;
use maarky\Jwt\Validator;

class OptionTest extends TestCase
{
    protected $srcJwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOjEyMzQ1Nn0.iJGpiQ7KAWGnbAkmKchWn99ZGjQX7kY0PwgwP_u9Jbw';
    protected $secret = 'secret';

    public function getValidator()
    {
        return new Validator($this->srcJwt, $this->secret);
    }

    public function testOption_Some()
    {
        $option = Option::create($this->getValidator());
        $this->assertTrue($option->isDefined());
    }

    public function testOption_None()
    {
        $this->assertTrue(Option::create(null)->isEmpty());
    }
}
