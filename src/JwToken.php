<?php


declare(strict_types=1);


namespace Omegaalfa\Jwtoken;

use InvalidArgumentException;
use JsonException;
use OpenSSLAsymmetricKey;
use Random\RandomException;
use function openssl_sign;
use function openssl_verify;

class JwToken
{
    use StreamHelperJwToken;

    /**
     * @var array<string, string>
     */
    private const array HMAC_ALGO_MAP = [
        'HS256' => 'sha256',
        'HS384' => 'sha384',
        'HS512' => 'sha512',
    ];

    /**
     * @var array<string, int>
     */
    private const array RSA_ALGO_MAP = [
        'RS256' => OPENSSL_ALGO_SHA256,
        'RS384' => OPENSSL_ALGO_SHA384,
        'RS512' => OPENSSL_ALGO_SHA512,
    ];

    private const array ALLOWED_ALGORITHMS = ['HS256', 'HS384', 'HS512', 'RS256', 'RS384', 'RS512'];
    private const int MAX_TOKEN_LENGTH = 8_192;
    /**
     * Maximum allowed timestamp value (10 years from now) to prevent integer overflow
     */
    private const int MAX_TIMESTAMP_OFFSET = 315360000; // 10 years in seconds
    /**
     * Pattern for valid kid values (alphanumeric, dash, underscore only)
     */
    private const string KID_PATTERN = '/^[a-zA-Z0-9_-]{1,64}$/';
    /**
     * Generic error message to prevent information disclosure
     */
    private const string GENERIC_VALIDATION_ERROR = 'Invalid token.';
    /**
     * @var string
     */
    public readonly string $secretKey;
    /**
     * @var string
     */
    public readonly string $algorithm;
    /**
     * @var string
     */
    public string $pathPrivateKey;
    /**
     * @var string
     */
    public string $pathPublicKey;
    /**
     * @var string|null
     */
    public ?string $expectedIssuer = null;
    /**
     * @var string|null
     */
    public ?string $expectedAudience = null;
    /**
     * @var int Default clock skew reduced to 10s for better security
     */
    private int $clockSkew = 10;
    /**
     * @var int Maximum age for iat claim (1 year)
     */
    private int $maxTokenAge = 31536000;
    /**
     * @var RevocationStoreInterface|null
     */
    public ?RevocationStoreInterface $revocationStore = null;
    /**
     * @var array<string, string>
     */
    private array $hmacKeys = [];
    /**
     * @var array<string, string>
     */
    private array $rsaPrivateKeyPaths = [];
    /**
     * @var array<string, string>
     */
    private array $rsaPublicKeyPaths = [];
    /**
     * @var OpenSSLAsymmetricKey|null
     */
    private ?OpenSSLAsymmetricKey $privateKey = null;
    /**
     * @var string Algorithm family (HMAC or RSA) - prevents key confusion attacks
     */
    private string $algorithmFamily;

    public function __construct(
        string $secretKey,
        string $algorithm = 'HS256',
        string $pathPrivateKey = '',
        string $pathPublicKey = '',
    )
    {
        $this->algorithm = strtoupper($algorithm);
        
        // Determine algorithm family for key confusion protection
        if (in_array($this->algorithm, ['HS256', 'HS384', 'HS512'], true)) {
            $this->algorithmFamily = 'HMAC';
            
            // Prevent using RSA keys as HMAC secrets
            if (str_contains($secretKey, 'BEGIN PUBLIC KEY') || 
                str_contains($secretKey, 'BEGIN RSA PUBLIC KEY') ||
                str_contains($secretKey, 'BEGIN PRIVATE KEY')) {
                throw new InvalidArgumentException('Cannot use RSA/PEM key as HMAC secret.');
            }
            
            // Enforce minimum secret length for HMAC
            if (strlen($secretKey) < 32) {
                throw new InvalidArgumentException('HMAC secret must be at least 32 bytes long.');
            }
        } else {
            $this->algorithmFamily = 'RSA';
        }
        
        $this->secretKey = $secretKey;
        $this->pathPrivateKey = $pathPrivateKey;
        $this->pathPublicKey = $pathPublicKey;

        $this->validateConfigStart();
    }

    /**
     * @return void
     */
    private function validateConfigStart(): void
    {
        // Explicit blacklist for 'none' algorithm
        $normalizedAlg = strtolower($this->algorithm);
        if ($normalizedAlg === 'none' || $normalizedAlg === '') {
            throw new InvalidArgumentException('Algorithm "none" is forbidden for security reasons.');
        }
        
        if (!in_array($this->algorithm, self::ALLOWED_ALGORITHMS, true)) {
            throw new InvalidArgumentException('Unsupported JWT algorithm.');
        }

        if (in_array($this->algorithm, ['RS256', 'RS384', 'RS512'], true)) {
            if (!file_exists($this->pathPrivateKey) || !file_exists($this->pathPublicKey)) {
                throw new InvalidArgumentException('Invalid token configuration.');
            }
        }
    }

    /**
     * @param array<string, string> $keys
     *
     * @return void
     */
    public function setHmacKeys(array $keys): void
    {
        $this->hmacKeys = $keys;
    }

    /**
     * @param array<string, string> $privateKeys
     * @param array<string, string> $publicKeys
     *
     * @return void
     */
    public function setRsaKeyPaths(array $privateKeys, array $publicKeys): void
    {
        $this->rsaPrivateKeyPaths = $privateKeys;
        $this->rsaPublicKeyPaths = $publicKeys;
    }

    /**
     * @param int $seconds Clock skew tolerance in seconds (max 300)
     * @return void
     */
    public function setClockSkew(int $seconds): void
    {
        if ($seconds < 0 || $seconds > 60) {
            throw new InvalidArgumentException('clockSkew must be between 0 and 60 seconds.');
        }
        $this->clockSkew = $seconds;
    }

    /**
     * @return int
     */
    public function getClockSkew(): int
    {
        return $this->clockSkew;
    }

    /**
     * @param int $seconds Maximum token age in seconds
     * @return void
     */
    public function setMaxTokenAge(int $seconds): void
    {
        if ($seconds < 60) {
            throw new InvalidArgumentException('maxTokenAge must be at least 60 seconds.');
        }
        $this->maxTokenAge = $seconds;
    }

    /**
     * @param mixed $payload
     * @param int $minutes
     * @param array<string, string> $options
     * @return string
     * @throws JsonException
     * @throws RandomException
     */
    public function createToken(mixed $payload, int $minutes = 120, array $options = []): string
    {
        // SECURITY: Validate expiration time bounds (max 10 years)
        $maxMinutes = self::MAX_TIMESTAMP_OFFSET / 60; // ~5,256,000 minutes
        if ($minutes < 1 || $minutes > $maxMinutes) {
            throw new InvalidArgumentException("Token expiration must be between 1 and {$maxMinutes} minutes.");
        }
        
        $payloadArray = $this->normalizePayload($payload);

        // SECURITY: Validate or set exp with bounds checking
        if (!isset($payloadArray['exp'])) {
            $payloadArray['exp'] = time() + (60 * $minutes);
        } else {
            // If exp was manually provided, validate bounds (but allow past dates for testing)
            if (!is_int($payloadArray['exp'])) {
                throw new InvalidArgumentException('exp claim must be an integer timestamp.');
            }
            
            $now = time();
            // SECURITY: Only reject timestamps that are clearly invalid (integer overflow protection)
            if ($payloadArray['exp'] > $now + self::MAX_TIMESTAMP_OFFSET) {
                throw new InvalidArgumentException('exp timestamp is too far in the future.');
            }
            
            // SECURITY: Reject timestamps before year 2000 (likely errors)
            if ($payloadArray['exp'] < 946684800) { // 2000-01-01 00:00:00 UTC
                throw new InvalidArgumentException('exp timestamp is invalid.');
            }
        }
        
        // SECURITY: Validate or add iat with bounds checking
        if (!isset($payloadArray['iat'])) {
            $payloadArray['iat'] = time();
        } else {
            // If iat was manually provided, validate bounds
            if (!is_int($payloadArray['iat'])) {
                throw new InvalidArgumentException('iat claim must be an integer timestamp.');
            }
            
            $now = time();
            // SECURITY: Reject timestamps that are clearly invalid
            if ($payloadArray['iat'] > $now + self::MAX_TIMESTAMP_OFFSET) {
                throw new InvalidArgumentException('iat timestamp is too far in the future.');
            }
            
            // SECURITY: Reject timestamps before year 2000 (likely errors)
            if ($payloadArray['iat'] < 946684800) {
                throw new InvalidArgumentException('iat timestamp is invalid.');
            }
        }
        
        // SECURITY: Validate nbf if provided
        if (isset($payloadArray['nbf'])) {
            if (!is_int($payloadArray['nbf'])) {
                throw new InvalidArgumentException('nbf claim must be an integer timestamp.');
            }
            
            $now = time();
            // SECURITY: Reject timestamps that are clearly invalid
            if ($payloadArray['nbf'] > $now + self::MAX_TIMESTAMP_OFFSET) {
                throw new InvalidArgumentException('nbf timestamp is too far in the future.');
            }
            
            // SECURITY: Reject timestamps before year 2000 (likely errors)
            if ($payloadArray['nbf'] < 946684800) {
                throw new InvalidArgumentException('nbf timestamp is invalid.');
            }
        }

        // SECURITY: Validate or generate jti
        if (!isset($payloadArray['jti'])) {
            $payloadArray['jti'] = bin2hex(random_bytes(16));
        } else {
            // Validate manually provided jti
            if (!is_string($payloadArray['jti']) || strlen($payloadArray['jti']) < 16 || strlen($payloadArray['jti']) > 128) {
                throw new InvalidArgumentException('jti must be a string between 16 and 128 characters.');
            }
        }

        $header = [
            'alg' => $this->algorithm,
            'typ' => 'JWT',
        ];

        // SECURITY: Validate kid format and existence before adding to header
        if (isset($options['kid'])) {
            $kid = $options['kid'];
            
            // Validate kid format
            if (!is_string($kid) || !preg_match(self::KID_PATTERN, $kid)) {
                throw new InvalidArgumentException('Invalid kid format. Only alphanumeric, dash, and underscore allowed (max 64 chars).');
            }
            
            // For HMAC, verify kid exists in hmacKeys
            if ($this->algorithmFamily === 'HMAC' && !isset($this->hmacKeys[$kid])) {
                throw new InvalidArgumentException('Unknown kid for HMAC algorithm.');
            }
            
            // For RSA, verify kid exists in rsaPrivateKeyPaths
            if ($this->algorithmFamily === 'RSA' && !isset($this->rsaPrivateKeyPaths[$kid])) {
                throw new InvalidArgumentException('Unknown kid for RSA algorithm.');
            }
            
            $header['kid'] = $kid;
        }

        $base64UrlHeader = $this->baseEncode(json_encode($header, JSON_THROW_ON_ERROR));
        $base64UrlPayload = $this->baseEncode(json_encode($payloadArray, JSON_THROW_ON_ERROR));

        $signature = $this->generateSignature($base64UrlHeader, $base64UrlPayload);
        $base64UrlSignature = $this->baseEncode($signature);

        return $base64UrlHeader . '.' . $base64UrlPayload . '.' . $base64UrlSignature;
    }

    /**
     * @param mixed $payload
     * @return array<string, mixed>
     */
    private function normalizePayload(mixed $payload): array
    {
        $this->validatePayload($payload);

        $payloadArray = is_array($payload) ? $payload : (array)$payload;
        /** @var array<string, mixed> $normalized */
        $normalized = [];

        foreach ($payloadArray as $key => $value) {
            $key = (string)$key;
            if (!is_int($value) && in_array($key, ['exp', 'iat', 'nbf'], true)) {
                throw new InvalidArgumentException("Claim {$key} must be an integer timestamp.");
            }
            $normalized[$key] = $value;
        }

        /** @var array<string,mixed> $normalized */
        return $normalized;
    }

    /**
     * @param mixed $payload
     *
     * @throws InvalidArgumentException
     */
    private function validatePayload(mixed $payload): void
    {
        if (!is_array($payload) && !is_object($payload)) {
            throw new InvalidArgumentException('Payload must be an array or an object.');
        }
    }

    /**
     * @param string $data
     *
     * @return string
     */
    private function baseEncode(string $data): string
    {
        $base64 = base64_encode($data);
        $base64Url = strtr($base64, '+/', '-_');

        return rtrim($base64Url, '=');
    }

    /**
     * @param string $base64UrlHeader
     * @param string $base64UrlPayload
     *
     * @return string
     * @throws JsonException
     */
    public function generateSignature(string $base64UrlHeader, string $base64UrlPayload): string
    {
        if (isset(self::RSA_ALGO_MAP[$this->algorithm])) {
            $headerDecoded = json_decode($this->baseDecode($base64UrlHeader), true, 512, JSON_THROW_ON_ERROR);
            if (!is_array($headerDecoded)) {
                throw new JsonException('Invalid JWT header.');
            }

            /** @var array<string, mixed> $headerArray */
            $headerArray = $headerDecoded;
            $privateKey = $this->loadPrivateKeyForHeader($headerArray);
            $opensslAlgo = self::RSA_ALGO_MAP[$this->algorithm];

            if (!openssl_sign($base64UrlHeader . '.' . $base64UrlPayload, $signature, $privateKey, $opensslAlgo)) {
                throw new JsonException('Failed to generate token signature.');
            }

            return $signature;
        }

        $headerDecoded = json_decode($this->baseDecode($base64UrlHeader), true, 512, JSON_THROW_ON_ERROR);
        if (!is_array($headerDecoded)) {
            throw new JsonException('Invalid JWT header.');
        }

        /** @var array<string, mixed> $headerArray */
        $headerArray = $headerDecoded;
        $secret = $this->resolveSecretKey($headerArray);

        return hash_hmac($this->resolveHmacAlgorithm(), $base64UrlHeader . '.' . $base64UrlPayload, $secret, true);
    }

    /**
     * @param array<string, mixed> $header
     *
     * @return OpenSSLAsymmetricKey
     * @throws JsonException
     */
    private function loadPrivateKeyForHeader(array $header): OpenSSLAsymmetricKey
    {
        $kid = $header['kid'] ?? null;

        if (is_string($kid)) {
            // SECURITY: Validate kid format to prevent path traversal
            if (!preg_match(self::KID_PATTERN, $kid)) {
                throw new JsonException('Authentication configuration error.');
            }
            
            if (!isset($this->rsaPrivateKeyPaths[$kid])) {
                throw new JsonException('Authentication configuration error.');
            }
            
            $pem = $this->readFile($this->rsaPrivateKeyPaths[$kid]);
            $privateKey = openssl_pkey_get_private($pem);
            if ($privateKey === false) {
                // Generic error message to prevent information disclosure
                throw new JsonException('Authentication configuration error.');
            }

            return $privateKey;
        }

        // No kid specified - use default key
        if ($this->privateKey instanceof OpenSSLAsymmetricKey) {
            return $this->privateKey;
        }

        $privateKey = openssl_pkey_get_private($this->readFile($this->pathPrivateKey));
        if ($privateKey === false) {
            // Generic error message to prevent information disclosure
            throw new JsonException('Authentication configuration error.');
        }

        return $this->privateKey = $privateKey;
    }

    /**
     * @param string $data
     * @return string
     * @throws JsonException
     */
    private function baseDecode(string $data): string
    {
        // Validate base64url characters
        if (!preg_match('/^[A-Za-z0-9_-]*$/', $data)) {
            throw new JsonException('Invalid base64url characters detected.');
        }
        
        $base64 = strtr($data, '-_', '+/');
        
        // Correct padding calculation
        $padLength = (4 - (strlen($base64) % 4)) % 4;
        $base64Padded = $base64 . str_repeat('=', $padLength);

        $decoded = base64_decode($base64Padded, true);
        if ($decoded === false) {
            throw new JsonException('Failed to decode base64-url encoded data.');
        }

        return $decoded;
    }

    /**
     * @param array<string, mixed> $header
     *
     * @return string
     */
    private function resolveSecretKey(array $header): string
    {
        $kid = $header['kid'] ?? null;

        if (is_string($kid)) {
            // SECURITY: Validate kid format to prevent path traversal and injection
            if (!preg_match(self::KID_PATTERN, $kid)) {
                throw new InvalidArgumentException(self::GENERIC_VALIDATION_ERROR);
            }
            
            if (isset($this->hmacKeys[$kid])) {
                return $this->hmacKeys[$kid];
            }
            
            // SECURITY: Fail if kid is specified but not found (don't fallback to default)
            throw new InvalidArgumentException(self::GENERIC_VALIDATION_ERROR);
        }

        return $this->secretKey;
    }

    /**
     * @param array<string, mixed> $header
     *
     * @return string
     */
    private function resolveRsaPublicKeyPath(array $header): string
    {
        $kid = $header['kid'] ?? null;

        if (is_string($kid)) {
            // SECURITY: Validate kid format to prevent path traversal
            if (!preg_match(self::KID_PATTERN, $kid)) {
                throw new InvalidArgumentException(self::GENERIC_VALIDATION_ERROR);
            }
            
            if (isset($this->rsaPublicKeyPaths[$kid])) {
                return $this->rsaPublicKeyPaths[$kid];
            }
            
            // SECURITY: Fail if kid is specified but not found
            throw new InvalidArgumentException(self::GENERIC_VALIDATION_ERROR);
        }

        return $this->pathPublicKey;
    }

    /**
     * @return string
     */
    private function resolveHmacAlgorithm(): string
    {
        return self::HMAC_ALGO_MAP[$this->algorithm] ?? 'sha256';
    }

    /**
     * @param string $token
     *
     * @return bool
     * @throws JsonException
     */
    public function validateToken(string $token): bool
    {
        // SECURITY: Trim whitespace before length check to prevent bypass
        $token = trim($token);
        
        if (strlen($token) > self::MAX_TOKEN_LENGTH) {
            throw new InvalidArgumentException(self::GENERIC_VALIDATION_ERROR);
        }

        $parts = explode('.', $token);
        if (count($parts) !== 3) {
            throw new InvalidArgumentException(self::GENERIC_VALIDATION_ERROR);
        }

        [$base64UrlHeader, $base64UrlPayload, $base64UrlSignature] = $parts;

        // SECURITY: Validate signature is not empty
        if (empty($base64UrlSignature)) {
            throw new InvalidArgumentException(self::GENERIC_VALIDATION_ERROR);
        }

        $headerDecoded = json_decode($this->baseDecode($base64UrlHeader), true, 512, JSON_THROW_ON_ERROR);
        if (!is_array($headerDecoded)) {
            throw new JsonException('Invalid JWT header.');
        }

        // SECURITY: Explicit validation against alg=none
        $headerAlg = $headerDecoded['alg'] ?? null;
        if (!is_string($headerAlg)) {
            throw new InvalidArgumentException(self::GENERIC_VALIDATION_ERROR);
        }
        
        if (strtolower($headerAlg) === 'none' || $headerAlg === '') {
            throw new InvalidArgumentException(self::GENERIC_VALIDATION_ERROR);
        }

        // SECURITY: Validate algorithm family matches (prevent key confusion)
        $isHeaderHmac = isset(self::HMAC_ALGO_MAP[$headerAlg]);
        $isHeaderRsa = isset(self::RSA_ALGO_MAP[$headerAlg]);
        
        if ($this->algorithmFamily === 'HMAC' && !$isHeaderHmac) {
            throw new InvalidArgumentException(self::GENERIC_VALIDATION_ERROR);
        }
        
        if ($this->algorithmFamily === 'RSA' && !$isHeaderRsa) {
            throw new InvalidArgumentException(self::GENERIC_VALIDATION_ERROR);
        }

        if ($headerAlg !== $this->algorithm) {
            throw new InvalidArgumentException(self::GENERIC_VALIDATION_ERROR);
        }
        
        // SECURITY: Validate typ header to prevent token type confusion
        $typ = $headerDecoded['typ'] ?? null;
        if ($typ !== 'JWT') {
            throw new InvalidArgumentException(self::GENERIC_VALIDATION_ERROR);
        }
        
        $payload = $this->decodePayload($base64UrlPayload);

        $signature = $this->baseDecode($base64UrlSignature);
        
        // SECURITY: Validate decoded signature is not empty
        if (empty($signature)) {
            throw new InvalidArgumentException(self::GENERIC_VALIDATION_ERROR);
        }

        if (isset(self::RSA_ALGO_MAP[$this->algorithm])) {
            $data = $base64UrlHeader . '.' . $base64UrlPayload;
            $publicKeyPath = $this->resolveRsaPublicKeyPath($headerDecoded);
            $publicKey = $this->readFile($publicKeyPath);
            $opensslAlgo = self::RSA_ALGO_MAP[$this->algorithm];

            // SECURITY FIX: Properly handle openssl_verify return values
            // Returns: 1 (valid), 0 (invalid), -1 (error)
            $verifyResult = openssl_verify($data, $signature, $publicKey, $opensslAlgo);
            
            if ($verifyResult === -1) {
                // OpenSSL error - always reject
                throw new JsonException('Signature verification failed.');
            }
            
            if ($verifyResult !== 1) {
                return false;
            }
        } else {
            $expectedSignature = $this->generateSignature($base64UrlHeader, $base64UrlPayload);

            if (!hash_equals($expectedSignature, $signature)) {
                return false;
            }
        }

        return $this->validatePayloadClaims($payload);
    }

    /**
     * @param string $base64UrlPayload
     *
     * @return array<string, mixed>
     * @throws JsonException
     */
    private function decodePayload(string $base64UrlPayload): array
    {
        $payload = $this->baseDecode($base64UrlPayload);

        $decoded = json_decode($payload, true, 512, JSON_THROW_ON_ERROR);

        if (!is_array($decoded)) {
            throw new JsonException('Payload inválido.');
        }

        /** @var array<string, mixed> $decoded */
        return $decoded;
    }

    /**
     * @param array<string, mixed> $payload
     *
     * @return bool
     */
    private function validatePayloadClaims(array $payload): bool
    {
        // SECURITY FIX: Check revocation FIRST to prevent race conditions
        if ($this->revocationStore !== null && isset($payload['jti']) && is_string($payload['jti'])) {
            if ($this->revocationStore->isRevoked($payload['jti'])) {
                return false; // Fail fast for revoked tokens
            }
        }
        
        $now = time();

        // SECURITY FIX: Validate exp with upper bound to prevent integer overflow
        if (isset($payload['exp']) && is_int($payload['exp'])) {
            // Prevent integer overflow: reject timestamps too far in the future
            if ($payload['exp'] > $now + self::MAX_TIMESTAMP_OFFSET) {
                return false;
            }
            
            if ($payload['exp'] < $now - $this->clockSkew) {
                return false;
            }
        }

        // SECURITY FIX: Validate nbf with upper bound
        if (isset($payload['nbf']) && is_int($payload['nbf'])) {
            // Prevent integer overflow
            if ($payload['nbf'] > $now + self::MAX_TIMESTAMP_OFFSET) {
                return false;
            }
            
            if ($payload['nbf'] > $now + $this->clockSkew) {
                return false;
            }
        }

        // SECURITY FIX: Validate iat with bounds
        if (isset($payload['iat']) && is_int($payload['iat'])) {
            // Reject tokens that are too old
            if ($payload['iat'] < $now - $this->maxTokenAge) {
                return false;
            }
            // Reject tokens issued in the future (with clock skew)
            if ($payload['iat'] > $now + $this->clockSkew) {
                return false;
            }
            // Prevent integer overflow: reject timestamps too far in the future
            if ($payload['iat'] > $now + self::MAX_TIMESTAMP_OFFSET) {
                return false;
            }
        }

        // iss
        if ($this->expectedIssuer !== null) {
            if (!isset($payload['iss']) || $payload['iss'] !== $this->expectedIssuer) {
                return false;
            }
        }

        // aud
        if ($this->expectedAudience !== null) {
            if (!isset($payload['aud'])) {
                return false;
            }
            $aud = $payload['aud'];
            $audList = is_array($aud) ? $aud : [$aud];
            if (!in_array($this->expectedAudience, $audList, true)) {
                return false;
            }
        }

        // All validations passed
        return true;
    }

    /**
     * @param string $token
     *
     * @return array<string, mixed>
     * @throws JsonException
     */
    public function decodeToken(string $token): array
    {
        $parts = explode('.', $token);
        if (count($parts) !== 3) {
            throw new InvalidArgumentException('Token inválido ou malformatado.');
        }

        [, $base64UrlPayload,] = $parts;

        return $this->decodePayload($base64UrlPayload);
    }
}
