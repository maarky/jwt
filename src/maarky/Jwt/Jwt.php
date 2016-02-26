<?php


namespace maarky\Jwt;

use maarky\Jwt\Mutable\Jwt as MutableJwt;
use maarky\Jwt\Immutable\Jwt as ImmutableJwt;
use maarky\Option\Option;
use maarky\Option\Type\String\Option as StringOption;
use maarky\Option\Type\Arr\Option as ArrayOption;

interface Jwt
{
    public function getHeader(string $key): Option;
    public function getHeaders(): ArrayOption;
    public function addHeader(string $key, $value): Jwt;
    public function addHeaders(array $headers): Jwt;
    public function removeHeader(string $key): Jwt;

    public function getSupportedAlgos(): array;
    public function setAlgo(string $algo): Jwt;
    public function setType(string $type): Jwt;

    public function getClaim(string $key): Option;
    public function getClaims(): ArrayOption;
    public function addClaim(string $key, $value): Jwt;
    public function addClaims(array $claims): Jwt;
    public function removeClaim(string $key): Jwt;

    public function setSecret($secret): Jwt;
    public function getSecret(): StringOption;

    public function isValid(): bool;
    public function encode(): string;

    public function addValidator(callable ...$validators): Jwt;
    public function getValidators(): ArrayOption;

    public function getMutable(): MutableJwt;
    public function getImmutable(): ImmutableJwt;
}