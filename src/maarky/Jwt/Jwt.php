<?php


namespace maarky\Jwt;

use maarky\Option\Option;
use maarky\Option\Type\String\Option as StringOption;

interface Jwt
{
    public function getHeader(string $key): Option;
    public function getHeaders(): array;

    public function getSupportedAlgs(): array;

    public function getClaim(string $key): Option;
    public function getClaims(): array;

    public function setSecret($secret): Jwt;
    public function getSecret(): StringOption;

    public function isValid(): bool;
    public function encode(): string;
    public function isTrusted(): bool;

    public function addValidator(string $name, callable $validator): Jwt;
    public function removeValidator(string $name): Jwt;
    public function clearValidators(): Jwt;
    public function getValidators(): array;
}