# JwToken

JwToken is a PHP library for creating, signing and validating JSON Web Tokens (JWT) with support for:

- HMAC (HS256, HS384, HS512)
- RSA (RS256)
- Temporal claims (`exp`, `nbf`, `iat`) and contextual claims (`iss`, `aud`)
- `jti` (JWT ID) with optional integration for revocation

> **Important:** this library is designed for production use. Make sure to read the “Security best practices” section before integrating.

## Installation

Via Composer:

```bash
composer require omegaalfa/jwtoken
```

## Requirements

- PHP: **8.4+**
- Extension: **ext-openssl**

## Concepts and features

- **HMAC algorithms (HS256/384/512)** via `hash_hmac`, with internal mapping to `sha256`, `sha384`, `sha512`.
- **RS256** via `openssl_sign` / `openssl_verify`, using private/public key files.
- **Supported claims:**
  - `exp` – expiration time, validated automatically.
  - `nbf` – not-before, rejects tokens used before the configured time.
  - `iat` – issued-at, can be used with configurable clock skew.
  - `iss` – issuer, compared against `expectedIssuer`.
  - `aud` – audience, compared against `expectedAudience`.
  - `jti` – JWT ID, generated automatically if missing and used with `RevocationStoreInterface`.
- **Additional protections:**
  - Maximum token length limit.
  - Safe parsing (3 segments, strict Base64/JSON decoding).
  - Constant-time comparison for HMAC signatures via `hash_equals` (timing attack protection).

## Basic usage with HMAC (HS256)

```php
use Omegaalfa\Jwtoken\JwToken;

$secret = getenv('JWT_SECRET');
if ($secret === false) {
    throw new RuntimeException('JWT_SECRET is not configured');
}

$jwt = new JwToken($secret, 'HS256');

// Optional: validation policy
$jwt->expectedIssuer = 'https://your-issuer.com';
$jwt->expectedAudience = 'your-api';

$payload = [
    'sub' => 'user-123',
    'name' => 'John Doe',
    'email' => 'john.doe@example.com',
    'iss' => 'https://your-issuer.com',
    'aud' => 'your-api',
    'iat' => time(),
    'exp' => time() + 3600,
];

$token = $jwt->createToken($payload);

// Validation
if ($jwt->validateToken($token)) {
    $decoded = $jwt->decodeToken($token);
    print_r($decoded);
}
```

## HMAC key rotation with `setHmacKeys` and `kid`

To make HMAC key rotation easier, you can register multiple secrets and use the `kid` header:

```php
use Omegaalfa\Jwtoken\JwToken;

$fallbackSecret = getenv('JWT_SECRET'); // default secret

$jwt = new JwToken($fallbackSecret, 'HS256');

// Register multiple secrets identified by kid
$jwt->setHmacKeys([
    'v1' => 'old-secret',
    'v2' => 'current-secret',
]);

// When issuing new tokens, always use the kid of the current key
$payload = [
    'sub' => 'user-123',
    'iss' => 'https://your-issuer.com',
    'aud' => 'your-api',
];

$token = $jwt->createToken($payload, 60, ['kid' => 'v2']);

// On validation, the header is decoded, kid is read and the correct key is used automatically
$jwt->validateToken($token); // true if the signature is consistent
```

If the header does not contain `kid` or the `kid` is not found in `setHmacKeys`, the library falls back to the `secretKey` provided in the constructor.

## Usage with RS256 (public/private key)

```php
use Omegaalfa\Jwtoken\JwToken;

$jwt = new JwToken(
    secretKey: 'not used for RS256',
    algorithm: 'RS256',
    pathPrivateKey: __DIR__ . '/keys/private.pem',
    pathPublicKey: __DIR__ . '/keys/public.pem',
);

$payload = [
    'sub' => 'user-123',
    'iss' => 'https://your-issuer.com',
    'aud' => 'your-api',
];

$token = $jwt->createToken($payload);

if ($jwt->validateToken($token)) {
    $decoded = $jwt->decodeToken($token);
}
```

Make sure your RSA keys have at least 2048 bits and are stored outside the public document root (e.g. `storage/keys` or a secure volume mounted in your container).

### RSA key rotation with `setRsaKeyPaths` and `kid`

Just like with HMAC, you can register multiple RSA key pairs and select which one to use via `kid`:

```php
use Omegaalfa\Jwtoken\JwToken;

$jwt = new JwToken(
    secretKey: 'not used for RS256',
    algorithm: 'RS256',
    pathPrivateKey: __DIR__ . '/keys/private_default.pem',
    pathPublicKey: __DIR__ . '/keys/public_default.pem',
);

// Register specific paths for each kid
$jwt->setRsaKeyPaths(
    [
        'k1' => __DIR__ . '/keys/private_v1.pem',
        'k2' => __DIR__ . '/keys/private_v2.pem',
    ],
    [
        'k1' => __DIR__ . '/keys/public_v1.pem',
        'k2' => __DIR__ . '/keys/public_v2.pem',
    ],
);

$payload = [
    'sub' => 'user-123',
    'iss' => 'https://your-issuer.com',
    'aud' => 'your-api',
];

// Generate token signed with key pair v2
$token = $jwt->createToken($payload, 60, ['kid' => 'k2']);

// On validation, the header is read, kid is resolved and the correct public key is used
$jwt->validateToken($token); // true if the key pair and kid match
```

If the `kid` provided does not exist in `setRsaKeyPaths`, the library falls back to the default `pathPrivateKey`/`pathPublicKey`.

#### Practical RSA rotation strategy

A common key rotation strategy:

1. **Introduce a new key**: generate a new key pair (`k2`) and configure it in `setRsaKeyPaths`, while keeping the old key (`k1`) for validation.
2. **Start signing with `k2`**: in all places that issue tokens, use `['kid' => 'k2']` in `createToken()`. Legacy tokens signed with `k1` remain valid because `k1` is still configured.
3. **Monitor `k1` usage**: use logs/telemetry to track when the volume of tokens using the old key becomes negligible.
4. **Decommission `k1`**: remove `k1` entries from `setRsaKeyPaths` (and/or update the default `pathPublicKey`) so that tokens signed with the old key are no longer accepted.

This flow allows for gradual rotation without locking out users, while keeping strict validation of `alg` and `kid`.

## Revocation and `jti`

All generated tokens receive a `jti` (unique JWT ID) when the payload does not provide one:

- If you configure `revocationStore` with an implementation of `RevocationStoreInterface`, you can revoke specific tokens.

Simple in-memory example (for tests only):

```php
use Omegaalfa\Jwtoken\RevocationStoreInterface;
use Omegaalfa\Jwtoken\JwToken;

class InMemoryRevocationStore implements RevocationStoreInterface
{
    public function __construct(private array $revoked = []) {}

    public function isRevoked(string $jti): bool
    {
        return in_array($jti, $this->revoked, true);
    }
}

$jwt = new JwToken('secret_key');
$jwt->revocationStore = new InMemoryRevocationStore(['compromised-jti']);
```

## Security best practices

- Always use strong secrets, stored in environment variables or a secret manager (never hard-coded).
- Prefer `HS512` or `RS256` unless compatibility requires otherwise.
- Set `expectedIssuer` and `expectedAudience` to ensure tokens are only valid in the intended context.
- Use short expiration times for access tokens (e.g. 5–15 minutes) and, if needed, implement a separate refresh token flow.
- Enable and configure revocation (`jti` + store) to support logout and revocation of compromised tokens.

## Recommended environment configuration (`php.ini`)

```ini
expose_php=0
display_errors=0
log_errors=1
session.cookie_secure=1
session.cookie_httponly=1
open_basedir=/app:/tmp
```
