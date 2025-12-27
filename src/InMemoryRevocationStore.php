<?php

declare(strict_types=1);

namespace Omegaalfa\Jwtoken;

class InMemoryRevocationStore implements RevocationStoreInterface
{
    /** @param string[] $revoked */
    public function __construct(private array $revoked = [])
    {
    }

    /**
     * @param string $jti
     * @return bool
     */
    public function isRevoked(string $jti): bool
    {
        return in_array($jti, $this->revoked, true);
    }

    /**
     * @param string $jti
     * @return void
     */
    public function add(string $jti): void
    {
        if (!in_array($jti, $this->revoked, true)) {
            $this->revoked[] = $jti;
        }
    }
}