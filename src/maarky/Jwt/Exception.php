<?php
declare(strict_types=1);

namespace maarky\Jwt;

class Exception extends \Exception
{
    const CANNOT_CHANGE_TYPE = 'Cannot change type.';
    const UNSUPPORTED_ALGO = 'Unsupported algo.';
    const UNSUPPORTED_CONSTRUCTOR_INPUT = 'The constructor does not support this input.';
    const CANNOT_DECODE_BASE64 = 'Cannot base64 decode.';
    const CANNOT_DECODE_JSON = 'Cannot json decode.';
    const CONSTRUCTOR_WITH_DOUBLE_ALGO = 'Cannot provide two algos.';
    const ENCODE_WITHOUT_ALG = 'Cannot encode without an algos.';
    const ENCODE_WITHOUT_SECRET = 'Cannot encode without a secret.';
    const ENCODE_WITHOUT_CLAIMS = 'Cannot encode without a claimset.';
    const VALIDATE_WITHOUT_JWT = 'Cannot validate without a jwt to compare it to.';
}