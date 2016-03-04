<?php

namespace maarky\Jwt\Mutable\Option;

use maarky\Jwt\Mutable\Jwt;

abstract class Option extends \maarky\Jwt\Option\Option
{
    protected function validate($value): bool
    {
        return parent::validate($value) && $value instanceof Jwt;
    }
}