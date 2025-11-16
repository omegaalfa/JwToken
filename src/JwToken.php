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

    private const array ALLOWED_ALGORITHMS = ['HS256', 'HS384', 'HS512', 'RS256'];
    private const int MAX_TOKEN_LENGTH = 8_192;
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
     * @var int
     */
    public int $clockSkew = 60;
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

    public function __construct(
        string $secretKey,
        string $algorithm = 'HS256',
        string $pathPrivateKey = '',
        string $pathPublicKey = '',
    )
    {
        $this->secretKey = $secretKey;
        $this->algorithm = strtoupper($algorithm);
        $this->pathPrivateKey = $pathPrivateKey;
        $this->pathPublicKey = $pathPublicKey;

        $this->validateConfigStart();
    }

    /**
     * @return void
     */
    private function validateConfigStart(): void
    {
        if (!in_array($this->algorithm, self::ALLOWED_ALGORITHMS, true)) {
            throw new InvalidArgumentException('Algoritmo JWT não suportado.');
        }

        if ($this->algorithm === 'RS256') {
            if (!file_exists($this->pathPrivateKey) || !file_exists($this->pathPublicKey)) {
                throw new InvalidArgumentException('public or private key path not provided or does not exist.');
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
     * @param mixed $payload
     * @param int $minutes
     * @param array<string, string> $options
     * @return string
     * @throws JsonException
     * @throws RandomException
     */
    public function createToken(mixed $payload, int $minutes = 120, array $options = []): string
    {
        $payloadArray = $this->normalizePayload($payload);

        if (!isset($payloadArray['exp'])) {
            $payloadArray['exp'] = time() + (60 * $minutes);
        }

        if (!isset($payloadArray['jti'])) {
            $payloadArray['jti'] = bin2hex(random_bytes(16));
        }

        if (!isset($payloadArray['jti'])) {
            $payloadArray['jti'] = bin2hex(random_bytes(16));
        }

        $header = [
            'alg' => $this->algorithm,
            'typ' => 'JWT',
        ];

        if (isset($options['kid'])) {
            $header['kid'] = $options['kid'];
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
        if ($this->algorithm === 'RS256') {
            $headerDecoded = json_decode($this->baseDecode($base64UrlHeader), true, 512, JSON_THROW_ON_ERROR);
            if (!is_array($headerDecoded)) {
                throw new JsonException('Invalid JWT header.');
            }

            /** @var array<string, mixed> $headerArray */
            $headerArray = $headerDecoded;
            $privateKey = $this->loadPrivateKeyForHeader($headerArray);

            if (!openssl_sign($base64UrlHeader . '.' . $base64UrlPayload, $signature, $privateKey, OPENSSL_ALGO_SHA256)) {
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

        if (is_string($kid) && isset($this->rsaPrivateKeyPaths[$kid])) {
            $pem = $this->readFile($this->rsaPrivateKeyPaths[$kid]);
            $privateKey = openssl_pkey_get_private($pem);
            if ($privateKey === false) {
                throw new JsonException('Failed to load private key for the provided kid.');
            }

            return $privateKey;
        }

        if ($this->privateKey instanceof OpenSSLAsymmetricKey) {
            return $this->privateKey;
        }

        $privateKey = openssl_pkey_get_private($this->readFile($this->pathPrivateKey));
        if ($privateKey === false) {
            throw new JsonException('Failed to load default private key.');
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
        $base64 = strtr($data, '-_', '+/');
        $base64Padded = str_pad($base64, strlen($base64) % 4, '=', STR_PAD_RIGHT);

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

        if (is_string($kid) && isset($this->hmacKeys[$kid])) {
            return $this->hmacKeys[$kid];
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

        if (is_string($kid) && isset($this->rsaPublicKeyPaths[$kid])) {
            return $this->rsaPublicKeyPaths[$kid];
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
        if (strlen($token) > self::MAX_TOKEN_LENGTH) {
            throw new InvalidArgumentException('Token muito extenso.');
        }

        $parts = explode('.', $token);
        if (count($parts) !== 3) {
            throw new InvalidArgumentException('Token inválido ou malformatado.');
        }

        [$base64UrlHeader, $base64UrlPayload, $base64UrlSignature] = $parts;

        $headerDecoded = json_decode($this->baseDecode($base64UrlHeader), true, 512, JSON_THROW_ON_ERROR);
        if (!is_array($headerDecoded)) {
            throw new JsonException('Invalid JWT header.');
        }

        if (($headerDecoded['alg'] ?? null) !== $this->algorithm) {
            throw new InvalidArgumentException('Algoritmo no header não corresponde ao configurado.');
        }
        $payload = $this->decodePayload($base64UrlPayload);

        $signature = $this->baseDecode($base64UrlSignature);

        if ($this->algorithm === 'RS256') {
            $data = $base64UrlHeader . '.' . $base64UrlPayload;
            $publicKeyPath = $this->resolveRsaPublicKeyPath($headerDecoded);
            $publicKey = $this->readFile($publicKeyPath);

            if (!openssl_verify($data, $signature, $publicKey, OPENSSL_ALGO_SHA256)) {
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
        $now = time();

        // exp
        if (isset($payload['exp']) && is_int($payload['exp']) && $payload['exp'] < $now - $this->clockSkew) {
            return false;
        }

        // nbf
        if (isset($payload['nbf']) && is_int($payload['nbf']) && $payload['nbf'] > $now + $this->clockSkew) {
            return false;
        }

        // iat
        if (isset($payload['iat']) && is_int($payload['iat']) && $payload['iat'] > $now + $this->clockSkew) {
            return false;
        }

        // iss
        if ($this->expectedIssuer !== null && (($payload['iss'] ?? null) !== $this->expectedIssuer)) {
            return false;
        }

        // aud
        if ($this->expectedAudience !== null) {
            $aud = $payload['aud'] ?? null;
            $audList = is_array($aud) ? $aud : [$aud];
            if (!in_array($this->expectedAudience, $audList, true)) {
                return false;
            }
        }

        // jti + revogação
        return !($this->revocationStore !== null && isset($payload['jti']) && is_string($payload['jti']) && $this->revocationStore->isRevoked($payload['jti']));
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
