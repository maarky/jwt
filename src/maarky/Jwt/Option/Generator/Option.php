<?php
declare(strict_types=1);

namespace maarky\Jwt\Option\Generator;

use maarky\Jwt\Generator;

abstract class Option extends \maarky\Option\Type\Object\Option
{
    public static function validate($value): bool
    {
        return $value instanceof Generator && parent::validate($value);
    }
}