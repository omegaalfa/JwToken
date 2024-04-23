<?php

namespace omegalfa\jwtoken;

use InvalidArgumentException;
use JsonException;

use function openssl_sign;

class JwToken
{
	use StreamHelperJwToken;

	/**
	 * @var resource|null
	 */
	private $privateKey = null;


	public function __construct(
		public readonly string $secretKey,
		public readonly string $algorithm = 'HS256',
		public string $pathPrivateKey = '',
		public string $pathPublicKey = '',
	) {
		$this->validateConfigStart();
	}

	/**
	 * @return void
	 */
	private function validateConfigStart(): void
	{
		if($this->algorithm === 'RS256') {
			if(!file_exists($this->pathPrivateKey) || !file_exists($this->pathPublicKey)) {
				throw new InvalidArgumentException('public or private key path not provided or does not exist.');
			}
		}
	}

	/**
	 * @param  mixed  $payload
	 * @param  int    $minutes
	 * @param  array  $options
	 *
	 * @return string
	 * @throws JsonException
	 */
	public function createToken(mixed $payload, int $minutes = 120, array $options = []): string
	{
		$this->validatePayload($payload);

		if(!isset($payload['exp'])) {
			$payload['exp'] = time() + (60 * $minutes);
		}

		$header = [
			'alg' => $this->algorithm,
			'typ' => 'JWT',
		];

		if(isset($options['kid'])) {
			$header['kid'] = $options['kid'];
		}

		$base64UrlHeader = $this->baseEncode(json_encode($header, JSON_THROW_ON_ERROR));
		$base64UrlPayload = $this->baseEncode(json_encode($payload, JSON_THROW_ON_ERROR));

		$signature = $this->generateSignature($base64UrlHeader, $base64UrlPayload);
		$base64UrlSignature = $this->baseEncode($signature);

		return $base64UrlHeader . '.' . $base64UrlPayload . '.' . $base64UrlSignature;
	}


	/**
	 * @param  string  $token
	 *
	 * @return bool
	 * @throws JsonException
	 */
	public function validateToken(string $token): bool
	{
		[$base64UrlHeader, $base64UrlPayload, $base64UrlSignature] = explode('.', $token);

		$signature = $this->baseDecode($base64UrlSignature);
		$expectedSignature = $this->generateSignature($base64UrlHeader, $base64UrlPayload);

		if($this->algorithm === 'RS256') {
			$publicKey = $this->readFile($this->pathPublicKey);
			$signature = $this->baseDecode($base64UrlSignature);
			$data = $base64UrlHeader . '.' . $base64UrlPayload;

			if(!openssl_verify($data, $signature, $publicKey, OPENSSL_ALGO_SHA256)) {
				return false;
			}
		}

		if(!hash_equals($signature, $expectedSignature)) {
			return false;
		}

		$payload = $this->decodePayload($base64UrlPayload);

		return $this->validatePayloadClaims($payload);
	}


	/**
	 * @param  string  $token
	 *
	 * @return mixed
	 * @throws JsonException
	 */
	public function decodeToken(string $token): mixed
	{
		[, $base64UrlPayload,] = explode('.', $token);
		$payload = $this->baseDecode($base64UrlPayload);

		return json_decode($payload, true, 512, JSON_THROW_ON_ERROR);
	}

	/**
	 * @param  string  $base64UrlHeader
	 * @param  string  $base64UrlPayload
	 *
	 * @return string
	 * @throws JsonException
	 */
	public function generateSignature(string $base64UrlHeader, string $base64UrlPayload): string
	{
		if($this->algorithm === 'RS256') {
			$privateKey = $this->privateKey ?? null;

			if(!$privateKey) {
				// Carregar a chave privada apenas na primeira vez
				$privateKey = $this->privateKey = openssl_pkey_get_private(
					$this->readFile($this->pathPrivateKey)
				);
			}

			if(!openssl_sign($base64UrlHeader . '.' . $base64UrlPayload, $signature, $privateKey, OPENSSL_ALGO_SHA256)) {
				throw new JsonException('Failed to generate token signature.');
			}

			return $signature;
		}

		return hash_hmac($this->verifiryHmac($this->algorithm), $base64UrlHeader . '.' . $base64UrlPayload, $this->secretKey, true);
	}

	/**
	 * @param  string  $algo
	 *
	 * @return string
	 */
	private function verifiryHmac(string $algo): string
	{
		if(in_array($algo, hash_hmac_algos())) {
			return $algo;
		}

		return 'sha256';
	}

	/**
	 * @param  mixed  $payload
	 *
	 * @throws InvalidArgumentException
	 */
	private function validatePayload(mixed $payload): void
	{
		if(!is_array($payload) && !is_object($payload)) {
			throw new InvalidArgumentException('Payload must be an array or an object.');
		}
	}

	/**
	 * @param  string  $base64UrlPayload
	 *
	 * @return mixed
	 * @throws JsonException
	 */
	private function decodePayload(string $base64UrlPayload): mixed
	{
		$payload = $this->baseDecode($base64UrlPayload);

		return json_decode($payload, true, 512, JSON_THROW_ON_ERROR);
	}

	/**
	 * @param  array  $payload
	 *
	 * @return bool
	 */
	private function validatePayloadClaims(array $payload): bool
	{
		return !(isset($payload['exp']) && $payload['exp'] < time());
	}


	/**
	 * @param  string  $data
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
	 * @param  string  $data
	 *
	 * @return bool|string
	 */
	private function baseDecode(string $data): bool|string
	{
		$base64 = strtr($data, '-_', '+/');
		$base64Padded = str_pad($base64, strlen($base64) % 4, '=', STR_PAD_RIGHT);

		return base64_decode($base64Padded);
	}
}
