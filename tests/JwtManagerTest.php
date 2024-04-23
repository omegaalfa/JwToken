<?php

namespace omegalfa\jwtoken\tests;

use PHPUnit\Framework\TestCase;
use src\auth\JwtManager;

class JwtManagerTest extends TestCase
{
	protected JwtManager $jwtManager;


	protected function setUp(): void
	{
		$this->jwtManager = new JwtManager('secret_key', 'sha256');
		$this->jwtManager->pathPrivateKey = 'path/to/private.key';
		$this->jwtManager->pathPublicKey = 'path/to/public.key';
	}

	public function testCreateToken()
	{
		// Teste para o método createToken
		$payload = ['user_id' => 123];
		$token = $this->jwtManager->createToken($payload);

		// Verifica se o token foi gerado corretamente
		$this->assertIsString($token);
		$this->assertNotEmpty($token);
	}

	public function testValidateToken()
	{
		// Teste para o método validateToken
		$payload = ['user_id' => 123];
		$token = $this->jwtManager->createToken($payload);

		// Verifica se o token é válido
		$isValid = $this->jwtManager->validateToken($token);
		$this->assertTrue($isValid);
	}

	public function testDecodeToken()
	{
		// Teste para o método decodeToken
		$payload = [
			'user_id' => '123',
			'exp' => time()
		];
		$token = $this->jwtManager->createToken($payload);

		// Decodifica o token e verifica o payload
		$decodedPayload = $this->jwtManager->decodeToken($token);
		$this->assertEquals($payload, $decodedPayload);
	}
}
