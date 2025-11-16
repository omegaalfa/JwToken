<?php


use Omegaalfa\Jwtoken\JwToken;
use PHPUnit\Framework\TestCase;


class JwtManagerTest extends TestCase
{
	protected JwToken $jwtManager;


	protected function setUp(): void
	{
		$this->jwtManager = new JwToken('secret_key');
		$this->jwtManager->pathPrivateKey = 'path/to/private.key';
		$this->jwtManager->pathPublicKey = 'path/to/public.key';
        $this->jwtManager->expectedIssuer = 'https://example-issuer';
        $this->jwtManager->expectedAudience = 'example-audience';
	}

	public function testCreateToken()
	{
		$payload = ['user_id' => 123];
		$token = $this->jwtManager->createToken($payload);

		// Verifica se o token foi gerado corretamente
		$this->assertIsString($token);
		$this->assertNotEmpty($token);
	}

	public function testValidateToken()
	{
		$payload = [
            'user_id' => 123,
            'iss' => 'https://example-issuer',
            'aud' => 'example-audience',
        ];
		$token = $this->jwtManager->createToken($payload);

		// Verifica se o token é válido
		$isValid = $this->jwtManager->validateToken($token);
		$this->assertTrue($isValid);
	}

	public function testDecodeToken()
		{
			$payload = [
	            'user_id' => '123',
	            'exp' => time(),
	            'iss' => 'https://example-issuer',
	            'aud' => 'example-audience',
	        ];
			$token = $this->jwtManager->createToken($payload);
	
			$decodedPayload = $this->jwtManager->decodeToken($token);

            foreach ($payload as $key => $value) {
                $this->assertArrayHasKey($key, $decodedPayload);
                $this->assertEquals($value, $decodedPayload[$key]);
            }
		}

    public function testExpiredTokenIsInvalid(): void
    {
        $payload = [
            'user_id' => 1,
            'exp' => time() - 3600,
            'iss' => 'https://example-issuer',
            'aud' => 'example-audience',
        ];

        $token = $this->jwtManager->createToken($payload);
        $this->assertFalse($this->jwtManager->validateToken($token));
    }

    public function testNotBeforeInFutureIsInvalid(): void
    {
        $payload = [
            'user_id' => 1,
            'nbf' => time() + 3600,
            'iss' => 'https://example-issuer',
            'aud' => 'example-audience',
        ];

        $token = $this->jwtManager->createToken($payload);
        $this->assertFalse($this->jwtManager->validateToken($token));
    }

    public function testIssuerMismatchIsInvalid(): void
    {
        $payload = [
            'user_id' => 1,
            'iss' => 'https://other-issuer',
            'aud' => 'example-audience',
        ];

        $token = $this->jwtManager->createToken($payload);
        $this->assertFalse($this->jwtManager->validateToken($token));
    }

    public function testAudienceMismatchIsInvalid(): void
    {
        $payload = [
            'user_id' => 1,
            'iss' => 'https://example-issuer',
            'aud' => 'other-audience',
        ];

        $token = $this->jwtManager->createToken($payload);
        $this->assertFalse($this->jwtManager->validateToken($token));
    }

    public function testSetHmacKeysUsesKidSecret(): void
    {
        $jwt = new JwToken('fallback_secret', 'HS256');

        // registra duas chaves diferentes
        $jwt->setHmacKeys([
            'v1' => 'secret_v1',
            'v2' => 'secret_v2',
        ]);

        $payload = ['user_id' => 1];

        // token assinado com v2
        $token = $jwt->createToken($payload, 60, ['kid' => 'v2']);

        // validação usando a mesma configuração deve ser true
        $this->assertTrue($jwt->validateToken($token));
    }

	    public function testDifferentHmacKeyFailsValidation(): void
	    {
	        $issuer = 'https://example-issuer';
	        $audience = 'example-audience';
	
	        // emissor com chave v1
	        $emissor = new JwToken('fallback_secret', 'HS256');
	        $emissor->expectedIssuer = $issuer;
	        $emissor->expectedAudience = $audience;
	        $emissor->setHmacKeys([
	            'v1' => 'secret_v1',
	        ]);
	
	        $payload = [
	            'user_id' => 1,
	            'iss' => $issuer,
	            'aud' => $audience,
	        ];
	
	        $token = $emissor->createToken($payload, 60, ['kid' => 'v1']);
	
	        // validador com chave diferente em v1
	        $validador = new JwToken('fallback_secret', 'HS256');
	        $validador->expectedIssuer = $issuer;
	        $validador->expectedAudience = $audience;
	        $validador->setHmacKeys([
	            'v1' => 'secret_v1_alterada',
	        ]);
	
	        $this->assertFalse($validador->validateToken($token));
	    }

        public function testAlgMismatchThrowsException(): void
        {
            $secret = 'secret_key';

            $jwtHs256 = new JwToken($secret, 'HS256');
            $payload = ['user_id' => 1];
            $token = $jwtHs256->createToken($payload);

            $jwtHs512 = new JwToken($secret, 'HS512');

            $this->expectException(\InvalidArgumentException::class);
            $jwtHs512->validateToken($token);
        }

        public function testRs256TokenWithKidIsValid(): void
        {
            [$privPath, $pubPath] = $this->generateRsaKeyPair();

            $jwt = new JwToken('dummy', 'RS256', $privPath, $pubPath);
            $jwt->setRsaKeyPaths(
                ['k1' => $privPath],
                ['k1' => $pubPath]
            );

            $payload = ['user_id' => 1];
            $token = $jwt->createToken($payload, 60, ['kid' => 'k1']);

            $this->assertTrue($jwt->validateToken($token));
        }

        public function testRs256TokenFailsWithWrongPublicKeyForKid(): void
        {
            [$priv1, $pub1] = $this->generateRsaKeyPair();
            [$priv2, $pub2] = $this->generateRsaKeyPair();

            // emissor com par de chaves 1
            $emissor = new JwToken('dummy', 'RS256', $priv1, $pub1);
            $emissor->setRsaKeyPaths(
                ['k1' => $priv1],
                ['k1' => $pub1]
            );

            $payload = ['user_id' => 1];
            $token = $emissor->createToken($payload, 60, ['kid' => 'k1']);

            // validador com chave pública diferente para o mesmo kid
            $validador = new JwToken('dummy', 'RS256', $priv2, $pub2);
            $validador->setRsaKeyPaths(
                ['k1' => $priv2],
                ['k1' => $pub2]
            );

            $this->assertFalse($validador->validateToken($token));
        }

        /**
         * @return array{0:string,1:string}
         */
        private function generateRsaKeyPair(): array
        {
            $config = [
                'private_key_type' => OPENSSL_KEYTYPE_RSA,
                'private_key_bits' => 2048,
            ];

            $res = openssl_pkey_new($config);
            $this->assertNotFalse($res);

            $privateKeyPem = '';
            openssl_pkey_export($res, $privateKeyPem);

            $details = openssl_pkey_get_details($res);
            $publicKeyPem = $details['key'] ?? null;
            $this->assertIsString($publicKeyPem);

            $dir = sys_get_temp_dir();
            $privPath = tempnam($dir, 'jwt_priv_') ?: $dir . '/jwt_priv_' . uniqid();
            $pubPath = tempnam($dir, 'jwt_pub_') ?: $dir . '/jwt_pub_' . uniqid();

            file_put_contents($privPath, $privateKeyPem);
            file_put_contents($pubPath, $publicKeyPem);

            return [$privPath, $pubPath];
        }
	}
