<?php

namespace maarky\Jwt\Option;

use maarky\Jwt\Jwt;

abstract class Option extends \maarky\Option\Type\Object\Option
{
    protected function validate($value): bool
    {
        return parent::validate($value) && $value instanceof Jwt;
    }
}