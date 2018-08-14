<?php
declare(strict_types=1);

namespace maarky\Jwt\Option\Validator;

use maarky\Jwt\Validator;

abstract class Option extends \maarky\Option\Type\Object\Option
{
    public static function validate($value): bool
    {
        return $value instanceof Validator && parent::validate($value);
    }
}