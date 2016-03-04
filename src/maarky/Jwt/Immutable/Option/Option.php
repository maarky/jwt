<?php

namespace maarky\Jwt\Immutable\Option;

use maarky\Jwt\Immutable\Jwt;

abstract class Option extends \maarky\Jwt\Option\Option
{
    protected function validate($value): bool
    {
        return parent::validate($value) && $value instanceof Jwt;
    }
}