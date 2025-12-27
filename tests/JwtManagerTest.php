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

    public function testSetClockSkew(): void
    {
        $jwt = new JwToken('secret');
        $jwt->setClockSkew(120);
        $this->assertEquals(120, $jwt->getClockSkew());
    }

    public function testSetClockSkewThrowsExceptionForNegativeValue(): void
    {
        $jwt = new JwToken('secret');
        
        $this->expectException(\InvalidArgumentException::class);
        $jwt->setClockSkew(-10);
    }

    public function testSetClockSkewThrowsExceptionForTooLargeValue(): void
    {
        $jwt = new JwToken('secret');
        
        $this->expectException(\InvalidArgumentException::class);
        $jwt->setClockSkew(301);
    }

    public function testSetMaxTokenAge(): void
    {
        $jwt = new JwToken('secret');
        $jwt->setMaxTokenAge(86400);
        
        $payload = ['user_id' => 1];
        $token = $jwt->createToken($payload);
        
        $this->assertTrue($jwt->validateToken($token));
    }

    public function testSetMaxTokenAgeThrowsExceptionForTooSmallValue(): void
    {
        $jwt = new JwToken('secret');
        
        $this->expectException(\InvalidArgumentException::class);
        $jwt->setMaxTokenAge(30);
    }

    public function testOldTokenIsRejected(): void
    {
        $jwt = new JwToken('secret');
        $jwt->setMaxTokenAge(86400); // 1 dia
        
        $payload = [
            'user_id' => 1,
            'iat' => time() - (86400 * 2), // 2 dias atrás
        ];
        
        $token = $jwt->createToken($payload);
        $this->assertFalse($jwt->validateToken($token));
    }

    public function testTokenWithFutureIatIsRejected(): void
    {
        $jwt = new JwToken('secret');
        
        $payload = [
            'user_id' => 1,
            'iat' => time() + 3600, // 1 hora no futuro (além do clock skew)
        ];
        
        $token = $jwt->createToken($payload);
        $this->assertFalse($jwt->validateToken($token));
    }

    public function testMissingIssuerWhenExpectedIsRejected(): void
    {
        $jwt = new JwToken('secret');
        $jwt->expectedIssuer = 'https://example.com';
        
        $payload = ['user_id' => 1]; // sem 'iss'
        $token = $jwt->createToken($payload);
        
        $this->assertFalse($jwt->validateToken($token));
    }

    public function testMissingAudienceWhenExpectedIsRejected(): void
    {
        $jwt = new JwToken('secret');
        $jwt->expectedAudience = 'my-api';
        
        $payload = ['user_id' => 1]; // sem 'aud'
        $token = $jwt->createToken($payload);
        
        $this->assertFalse($jwt->validateToken($token));
    }

    public function testAudienceAsArray(): void
    {
        $jwt = new JwToken('secret');
        $jwt->expectedAudience = 'api-2';
        
        $payload = [
            'user_id' => 1,
            'aud' => ['api-1', 'api-2', 'api-3'],
        ];
        
        $token = $jwt->createToken($payload);
        $this->assertTrue($jwt->validateToken($token));
    }

    public function testRevocationStoreBlocksToken(): void
    {
        $jwt = new JwToken('secret');
        
        $payload = ['user_id' => 1];
        $token = $jwt->createToken($payload);
        $decoded = $jwt->decodeToken($token);
        
        // Adiciona o jti à lista de revogados
        $revokedStore = new \Omegaalfa\Jwtoken\InMemoryRevocationStore([$decoded['jti']]);
        $jwt->revocationStore = $revokedStore;
        
        $this->assertFalse($jwt->validateToken($token));
    }

    public function testTokenTooLongIsRejected(): void
    {
        $jwt = new JwToken('secret');
        
        $this->expectException(\InvalidArgumentException::class);
        $jwt->validateToken(str_repeat('a', 8200));
    }

    public function testMalformedTokenIsRejected(): void
    {
        $jwt = new JwToken('secret');
        
        $this->expectException(\InvalidArgumentException::class);
        $jwt->validateToken('invalid.token');
    }

    public function testDecodeTokenThrowsExceptionForMalformedToken(): void
    {
        $jwt = new JwToken('secret');
        
        $this->expectException(\InvalidArgumentException::class);
        $jwt->decodeToken('bad.token');
    }

    public function testUnsupportedAlgorithmThrowsException(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new JwToken('secret', 'NONE');
    }

    public function testRS256WithoutKeysThrowsException(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new JwToken('secret', 'RS256', '', '');
    }

    public function testHS384Algorithm(): void
    {
        $jwt = new JwToken('my-secret-384', 'HS384');
        
        $payload = ['user_id' => 99];
        $token = $jwt->createToken($payload);
        
        $this->assertTrue($jwt->validateToken($token));
    }

    public function testHS512Algorithm(): void
    {
        $jwt = new JwToken('my-secret-512', 'HS512');
        
        $payload = ['user_id' => 88];
        $token = $jwt->createToken($payload);
        
        $this->assertTrue($jwt->validateToken($token));
    }

    public function testCustomExpirationTime(): void
    {
        $jwt = new JwToken('secret');
        
        $customExp = time() + 7200;
        $payload = [
            'user_id' => 1,
            'exp' => $customExp,
        ];
        
        $token = $jwt->createToken($payload);
        $decoded = $jwt->decodeToken($token);
        
        $this->assertEquals($customExp, $decoded['exp']);
    }

    public function testAutoGeneratedJti(): void
    {
        $jwt = new JwToken('secret');
        
        $payload = ['user_id' => 1];
        $token = $jwt->createToken($payload);
        
        $decoded = $jwt->decodeToken($token);
        $this->assertArrayHasKey('jti', $decoded);
        $this->assertIsString($decoded['jti']);
        $this->assertNotEmpty($decoded['jti']);
    }

    public function testCustomJtiIsPreserved(): void
    {
        $jwt = new JwToken('secret');
        
        $customJti = 'my-custom-jti-12345';
        $payload = [
            'user_id' => 1,
            'jti' => $customJti,
        ];
        
        $token = $jwt->createToken($payload);
        $decoded = $jwt->decodeToken($token);
        
        $this->assertEquals($customJti, $decoded['jti']);
    }

    public function testInvalidPayloadTypeThrowsException(): void
    {
        $jwt = new JwToken('secret');
        
        $this->expectException(\InvalidArgumentException::class);
        $jwt->createToken('invalid_payload');
    }

    public function testNonIntegerExpClaimThrowsException(): void
    {
        $jwt = new JwToken('secret');
        
        $payload = [
            'user_id' => 1,
            'exp' => 'not-an-int',
        ];
        
        $this->expectException(\InvalidArgumentException::class);
        $jwt->createToken($payload);
    }

    public function testNonIntegerIatClaimThrowsException(): void
    {
        $jwt = new JwToken('secret');
        
        $payload = [
            'user_id' => 1,
            'iat' => 'not-an-int',
        ];
        
        $this->expectException(\InvalidArgumentException::class);
        $jwt->createToken($payload);
    }

    public function testNonIntegerNbfClaimThrowsException(): void
    {
        $jwt = new JwToken('secret');
        
        $payload = [
            'user_id' => 1,
            'nbf' => 'not-an-int',
        ];
        
        $this->expectException(\InvalidArgumentException::class);
        $jwt->createToken($payload);
    }

    public function testInMemoryRevocationStoreAdd(): void
    {
        $store = new \Omegaalfa\Jwtoken\InMemoryRevocationStore();
        
        $this->assertFalse($store->isRevoked('test-jti'));
        
        $store->add('test-jti');
        $this->assertTrue($store->isRevoked('test-jti'));
        
        // Adicionar novamente não deve duplicar
        $store->add('test-jti');
        $this->assertTrue($store->isRevoked('test-jti'));
    }
}
