<?php

namespace omegalfa\jwtoken;

use InvalidArgumentException;
use JsonException;

class JwToken
{
	/**
	 * @var string
	 */
	private string $secretKey;

	/**
	 * @param  string  $secretKey
	 */
	public function __construct(string $secretKey)
	{
		$this->secretKey = $secretKey;
	}


	/**
	 * @param  mixed  $payload
	 * @param  int    $minutes
	 *
	 * @return string
	 * @throws JsonException
	 */
	public function createToken(mixed $payload, int $minutes = 120): string
	{
		if(!is_array($payload) && !is_object($payload)) {
			throw new InvalidArgumentException('Payload deve ser um array ou um objeto.');
		}

		if(!isset($payload['exp'])) {
			$payload['exp'] = time() + (60 * $minutes);
		}
		
		$base64UrlHeader = $this->baseEncode(json_encode(["alg" => "HS256", "typ" => "JWT"], JSON_THROW_ON_ERROR));
		$base64UrlPayload = $this->baseEncode(json_encode($payload, JSON_THROW_ON_ERROR));
		$base64UrlSignature = hash_hmac('sha256', $base64UrlHeader . '.' . $base64UrlPayload, $this->secretKey, true);
		$base64UrlSignature = $this->baseEncode($base64UrlSignature);

		return $base64UrlHeader . '.' . $base64UrlPayload . '.' . $base64UrlSignature;
	}


	/**
	 * @param  string  $token
	 *
	 * @return bool
	 */
	public function validateToken(string $token): bool
	{
		[$base64UrlHeader, $base64UrlPayload, $base64UrlSignature] = explode('.', $token);

		$signature = $this->baseDecode($base64UrlSignature);
		$expectedSignature = hash_hmac('sha256', $base64UrlHeader . '.' . $base64UrlPayload, $this->secretKey, true);

		if(!hash_equals($signature, $expectedSignature)) {
			return false;
		}

		try {
			$payload = json_decode($this->baseDecode($base64UrlPayload), true, 512, JSON_THROW_ON_ERROR);
		} catch(JsonException) {
			return false;
		}

		if($payload['exp'] < time()) {
			return false;
		}

		return true;
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
}
