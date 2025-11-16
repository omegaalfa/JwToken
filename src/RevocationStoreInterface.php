<?php

declare(strict_types=1);

namespace Omegaalfa\Jwtoken;

interface RevocationStoreInterface
{
    public function isRevoked(string $jti): bool;
}

