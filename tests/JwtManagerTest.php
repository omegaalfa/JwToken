<?php


use Omegaalfa\Jwtoken\JwToken;
use PHPUnit\Framework\TestCase;


class JwtManagerTest extends TestCase
{
	protected JwToken $jwtManager;


	protected function setUp(): void
	{
		// Use a 32-byte secret as required by security hardening
		$this->jwtManager = new JwToken('this-is-a-secure-32-byte-secret-key-for-testing');
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
        $jwt = new JwToken('this-is-a-secure-32-byte-fallback-secret', 'HS256');

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
	        $emissor = new JwToken('this-is-a-secure-32-byte-fallback-secret', 'HS256');
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
	        $validador = new JwToken('this-is-a-secure-32-byte-fallback-secret', 'HS256');
	        $validador->expectedIssuer = $issuer;
	        $validador->expectedAudience = $audience;
	        $validador->setHmacKeys([
	            'v1' => 'secret_v1_alterada',
	        ]);
	
	        $this->assertFalse($validador->validateToken($token));
	    }

        public function testAlgMismatchThrowsException(): void
        {
            $secret = 'this-is-a-secure-32-byte-secret-key-for-testing';

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

            $jwt = new JwToken('this-is-a-dummy-32-byte-secret-for-rsa-alg', 'RS256', $privPath, $pubPath);
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
            $emissor = new JwToken('this-is-a-dummy-32-byte-secret-for-rsa-alg', 'RS256', $priv1, $pub1);
            $emissor->setRsaKeyPaths(
                ['k1' => $priv1],
                ['k1' => $pub1]
            );

            $payload = ['user_id' => 1];
            $token = $emissor->createToken($payload, 60, ['kid' => 'k1']);

            // validador com chave pública diferente para o mesmo kid
            $validador = new JwToken('this-is-a-dummy-32-byte-secret-for-rsa-alg', 'RS256', $priv2, $pub2);
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
        $jwt = new JwToken('this-is-a-secure-32-byte-secret-key-for-testing');
        $jwt->setClockSkew(30);
        $this->assertEquals(30, $jwt->getClockSkew());
    }

    public function testSetClockSkewThrowsExceptionForNegativeValue(): void
    {
        $jwt = new JwToken('this-is-a-secure-32-byte-secret-key-for-testing');
        
        $this->expectException(\InvalidArgumentException::class);
        $jwt->setClockSkew(-10);
    }

    public function testSetClockSkewThrowsExceptionForTooLargeValue(): void
    {
        $jwt = new JwToken('this-is-a-secure-32-byte-secret-key-for-testing');
        
        $this->expectException(\InvalidArgumentException::class);
        $jwt->setClockSkew(301);
    }

    public function testSetMaxTokenAge(): void
    {
        $jwt = new JwToken('this-is-a-secure-32-byte-secret-key-for-testing');
        $jwt->setMaxTokenAge(86400);
        
        $payload = ['user_id' => 1];
        $token = $jwt->createToken($payload);
        
        $this->assertTrue($jwt->validateToken($token));
    }

    public function testSetMaxTokenAgeThrowsExceptionForTooSmallValue(): void
    {
        $jwt = new JwToken('this-is-a-secure-32-byte-secret-key-for-testing');
        
        $this->expectException(\InvalidArgumentException::class);
        $jwt->setMaxTokenAge(30);
    }

    public function testOldTokenIsRejected(): void
    {
        $jwt = new JwToken('this-is-a-secure-32-byte-secret-key-for-testing');
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
        $jwt = new JwToken('this-is-a-secure-32-byte-secret-key-for-testing');
        
        $payload = [
            'user_id' => 1,
            'iat' => time() + 3600, // 1 hora no futuro (além do clock skew)
        ];
        
        $token = $jwt->createToken($payload);
        $this->assertFalse($jwt->validateToken($token));
    }

    public function testMissingIssuerWhenExpectedIsRejected(): void
    {
        $jwt = new JwToken('this-is-a-secure-32-byte-secret-key-for-testing');
        $jwt->expectedIssuer = 'https://example.com';
        
        $payload = ['user_id' => 1]; // sem 'iss'
        $token = $jwt->createToken($payload);
        
        $this->assertFalse($jwt->validateToken($token));
    }

    public function testMissingAudienceWhenExpectedIsRejected(): void
    {
        $jwt = new JwToken('this-is-a-secure-32-byte-secret-key-for-testing');
        $jwt->expectedAudience = 'my-api';
        
        $payload = ['user_id' => 1]; // sem 'aud'
        $token = $jwt->createToken($payload);
        
        $this->assertFalse($jwt->validateToken($token));
    }

    public function testAudienceAsArray(): void
    {
        $jwt = new JwToken('this-is-a-secure-32-byte-secret-key-for-testing');
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
        $jwt = new JwToken('this-is-a-secure-32-byte-secret-key-for-testing');
        
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
        $jwt = new JwToken('this-is-a-secure-32-byte-secret-key-for-testing');
        
        $this->expectException(\InvalidArgumentException::class);
        $jwt->validateToken(str_repeat('a', 8200));
    }

    public function testMalformedTokenIsRejected(): void
    {
        $jwt = new JwToken('this-is-a-secure-32-byte-secret-key-for-testing');
        
        $this->expectException(\InvalidArgumentException::class);
        $jwt->validateToken('invalid.token');
    }

    public function testDecodeTokenThrowsExceptionForMalformedToken(): void
    {
        $jwt = new JwToken('this-is-a-secure-32-byte-secret-key-for-testing');
        
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
        $jwt = new JwToken('this-is-a-secure-32-byte-secret-hs384-key', 'HS384');
        
        $payload = ['user_id' => 99];
        $token = $jwt->createToken($payload);
        
        $this->assertTrue($jwt->validateToken($token));
    }

    public function testHS512Algorithm(): void
    {
        $jwt = new JwToken('this-is-a-secure-32-byte-secret-hs512-key', 'HS512');
        
        $payload = ['user_id' => 88];
        $token = $jwt->createToken($payload);
        
        $this->assertTrue($jwt->validateToken($token));
    }

    public function testCustomExpirationTime(): void
    {
        $jwt = new JwToken('this-is-a-secure-32-byte-secret-key-for-testing');
        
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
        $jwt = new JwToken('this-is-a-secure-32-byte-secret-key-for-testing');
        
        $payload = ['user_id' => 1];
        $token = $jwt->createToken($payload);
        
        $decoded = $jwt->decodeToken($token);
        $this->assertArrayHasKey('jti', $decoded);
        $this->assertIsString($decoded['jti']);
        $this->assertNotEmpty($decoded['jti']);
    }

    public function testCustomJtiIsPreserved(): void
    {
        $jwt = new JwToken('this-is-a-secure-32-byte-secret-key-for-testing');
        
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
        $jwt = new JwToken('this-is-a-secure-32-byte-secret-key-for-testing');
        
        $this->expectException(\InvalidArgumentException::class);
        $jwt->createToken('invalid_payload');
    }

    public function testNonIntegerExpClaimThrowsException(): void
    {
        $jwt = new JwToken('this-is-a-secure-32-byte-secret-key-for-testing');
        
        $payload = [
            'user_id' => 1,
            'exp' => 'not-an-int',
        ];
        
        $this->expectException(\InvalidArgumentException::class);
        $jwt->createToken($payload);
    }

    public function testNonIntegerIatClaimThrowsException(): void
    {
        $jwt = new JwToken('this-is-a-secure-32-byte-secret-key-for-testing');
        
        $payload = [
            'user_id' => 1,
            'iat' => 'not-an-int',
        ];
        
        $this->expectException(\InvalidArgumentException::class);
        $jwt->createToken($payload);
    }

    public function testNonIntegerNbfClaimThrowsException(): void
    {
        $jwt = new JwToken('this-is-a-secure-32-byte-secret-key-for-testing');
        
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

    public function testRS384Algorithm(): void
    {
        [$privPath, $pubPath] = $this->generateRsaKeyPair();

        $jwt = new JwToken('secret', 'RS384', $privPath, $pubPath);

        $payload = ['user_id' => 123, 'name' => 'Test User'];
        $token = $jwt->createToken($payload);

        $this->assertIsString($token);
        $this->assertTrue($jwt->validateToken($token));

        $decoded = $jwt->decodeToken($token);
        $this->assertEquals(123, $decoded['user_id']);
        $this->assertEquals('Test User', $decoded['name']);

        unlink($privPath);
        unlink($pubPath);
    }

    public function testRS512Algorithm(): void
    {
        [$privPath, $pubPath] = $this->generateRsaKeyPair();

        $jwt = new JwToken('secret', 'RS512', $privPath, $pubPath);

        $payload = ['user_id' => 456, 'role' => 'admin'];
        $token = $jwt->createToken($payload);

        $this->assertIsString($token);
        $this->assertTrue($jwt->validateToken($token));

        $decoded = $jwt->decodeToken($token);
        $this->assertEquals(456, $decoded['user_id']);
        $this->assertEquals('admin', $decoded['role']);

        unlink($privPath);
        unlink($pubPath);
    }

    public function testRS384WithInvalidSignatureFails(): void
    {
        [$privPath1, $pubPath1] = $this->generateRsaKeyPair();
        [$privPath2, $pubPath2] = $this->generateRsaKeyPair();

        $jwtSigner = new JwToken('secret', 'RS384', $privPath1, $pubPath1);
        $jwtValidator = new JwToken('secret', 'RS384', $privPath2, $pubPath2);

        $payload = ['user_id' => 789];
        $token = $jwtSigner->createToken($payload);

        $this->assertFalse($jwtValidator->validateToken($token));

        unlink($privPath1);
        unlink($pubPath1);
        unlink($privPath2);
        unlink($pubPath2);
    }

    public function testRS512WithInvalidSignatureFails(): void
    {
        [$privPath1, $pubPath1] = $this->generateRsaKeyPair();
        [$privPath2, $pubPath2] = $this->generateRsaKeyPair();

        $jwtSigner = new JwToken('secret', 'RS512', $privPath1, $pubPath1);
        $jwtValidator = new JwToken('secret', 'RS512', $privPath2, $pubPath2);

        $payload = ['user_id' => 999];
        $token = $jwtSigner->createToken($payload);

        $this->assertFalse($jwtValidator->validateToken($token));

        unlink($privPath1);
        unlink($pubPath1);
        unlink($privPath2);
        unlink($pubPath2);
    }

    public function testRS384WithKidRotation(): void
    {
        [$priv1, $pub1] = $this->generateRsaKeyPair();
        [$priv2, $pub2] = $this->generateRsaKeyPair();

        $jwt = new JwToken('secret', 'RS384', $priv1, $pub1);
        $jwt->setRsaKeyPaths(
            ['key1' => $priv1, 'key2' => $priv2],
            ['key1' => $pub1, 'key2' => $pub2]
        );

        $payload1 = ['user_id' => 1];
        $token1 = $jwt->createToken($payload1, 60, ['kid' => 'key1']);
        $this->assertTrue($jwt->validateToken($token1));

        $payload2 = ['user_id' => 2];
        $token2 = $jwt->createToken($payload2, 60, ['kid' => 'key2']);
        $this->assertTrue($jwt->validateToken($token2));

        unlink($priv1);
        unlink($pub1);
        unlink($priv2);
        unlink($pub2);
    }

    public function testRS512WithKidRotation(): void
    {
        [$priv1, $pub1] = $this->generateRsaKeyPair();
        [$priv2, $pub2] = $this->generateRsaKeyPair();

        $jwt = new JwToken('secret', 'RS512', $priv1, $pub1);
        $jwt->setRsaKeyPaths(
            ['k1' => $priv1, 'k2' => $priv2],
            ['k1' => $pub1, 'k2' => $pub2]
        );

        $payload1 = ['user_id' => 100];
        $token1 = $jwt->createToken($payload1, 60, ['kid' => 'k1']);
        $this->assertTrue($jwt->validateToken($token1));

        $payload2 = ['user_id' => 200];
        $token2 = $jwt->createToken($payload2, 60, ['kid' => 'k2']);
        $this->assertTrue($jwt->validateToken($token2));

        unlink($priv1);
        unlink($pub1);
        unlink($priv2);
        unlink($pub2);
    }

    public function testRS384RequiresKeyFiles(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new JwToken('secret', 'RS384', '', '');
    }

    public function testRS512RequiresKeyFiles(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new JwToken('secret', 'RS512', '', '');
    }

    public function testAlgorithmMismatchRS384Fails(): void
    {
        [$privPath, $pubPath] = $this->generateRsaKeyPair();

        $jwtRS384 = new JwToken('secret', 'RS384', $privPath, $pubPath);
        $jwtRS256 = new JwToken('secret', 'RS256', $privPath, $pubPath);

        $payload = ['user_id' => 1];
        $tokenRS384 = $jwtRS384->createToken($payload);

        $this->expectException(\InvalidArgumentException::class);
        $jwtRS256->validateToken($tokenRS384);

        unlink($privPath);
        unlink($pubPath);
    }

    public function testAlgorithmMismatchRS512Fails(): void
    {
        [$privPath, $pubPath] = $this->generateRsaKeyPair();

        $jwtRS512 = new JwToken('secret', 'RS512', $privPath, $pubPath);
        $jwtRS256 = new JwToken('secret', 'RS256', $privPath, $pubPath);

        $payload = ['user_id' => 1];
        $tokenRS512 = $jwtRS512->createToken($payload);

        $this->expectException(\InvalidArgumentException::class);
        $jwtRS256->validateToken($tokenRS512);

        unlink($privPath);
        unlink($pubPath);
    }
    
    // ===== RE-AUDIT SECURITY FIX TESTS =====
    
    public function testInvalidKidFormatInCreateTokenThrowsException(): void
    {
        $jwt = new JwToken('this-is-a-secure-32-byte-secret-key-for-testing');
        $jwt->setHmacKeys([
            'valid-kid' => 'this-is-a-secure-32-byte-secret-key-for-testing'
        ]);
        
        $payload = ['user_id' => 1];
        
        // Test path traversal attempt
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid kid format');
        $jwt->createToken($payload, 120, ['kid' => '../../../etc/passwd']);
    }
    
    public function testUnknownKidInCreateTokenThrowsException(): void
    {
        $jwt = new JwToken('this-is-a-secure-32-byte-secret-key-for-testing');
        $jwt->setHmacKeys([
            'valid-kid' => 'this-is-a-secure-32-byte-secret-key-for-testing'
        ]);
        
        $payload = ['user_id' => 1];
        
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Unknown kid for HMAC algorithm');
        $jwt->createToken($payload, 120, ['kid' => 'nonexistent-kid']);
    }
    
    public function testExpirationTooFarInFutureThrowsException(): void
    {
        $jwt = new JwToken('this-is-a-secure-32-byte-secret-key-for-testing');
        
        $payload = [
            'user_id' => 1,
            'exp' => time() + 315360001 // Slightly over MAX_TIMESTAMP_OFFSET
        ];
        
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('exp timestamp is too far in the future');
        $jwt->createToken($payload);
    }
    
    public function testExpirationBeforeYear2000ThrowsException(): void
    {
        $jwt = new JwToken('this-is-a-secure-32-byte-secret-key-for-testing');
        
        $payload = [
            'user_id' => 1,
            'exp' => 946684799 // 1 second before 2000-01-01
        ];
        
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('exp timestamp is invalid');
        $jwt->createToken($payload);
    }
    
    public function testInvalidJtiTypeThrowsException(): void
    {
        $jwt = new JwToken('this-is-a-secure-32-byte-secret-key-for-testing');
        
        $payload = [
            'user_id' => 1,
            'jti' => 123 // Integer instead of string
        ];
        
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('jti must be a string');
        $jwt->createToken($payload);
    }
    
    public function testJtiTooShortThrowsException(): void
    {
        $jwt = new JwToken('this-is-a-secure-32-byte-secret-key-for-testing');
        
        $payload = [
            'user_id' => 1,
            'jti' => 'short' // Less than 16 characters
        ];
        
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('jti must be a string between 16 and 128 characters');
        $jwt->createToken($payload);
    }
    
    public function testJtiTooLongThrowsException(): void
    {
        $jwt = new JwToken('this-is-a-secure-32-byte-secret-key-for-testing');
        
        $payload = [
            'user_id' => 1,
            'jti' => str_repeat('a', 129) // More than 128 characters
        ];
        
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('jti must be a string between 16 and 128 characters');
        $jwt->createToken($payload);
    }
    
    public function testMaxExpirationMinutesExceedsLimit(): void
    {
        $jwt = new JwToken('this-is-a-secure-32-byte-secret-key-for-testing');
        
        $payload = ['user_id' => 1];
        
        // Try to create token with expiration beyond MAX_TIMESTAMP_OFFSET
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Token expiration must be between');
        $jwt->createToken($payload, 315360000 / 60 + 1); // Exceed limit
    }
    public function testGenericErrorMessagesPreventInformationDisclosure(): void
    {
        $jwt = new JwToken('this-is-a-secure-32-byte-secret-key-for-testing');
        
        // Test 1: Token too long
        try {
            $jwt->validateToken(str_repeat('a', 8193));
            $this->fail('Should have thrown exception');
        } catch (\InvalidArgumentException $e) {
            $this->assertEquals('Invalid token.', $e->getMessage());
        }
        
        // Test 2: Token with wrong number of parts
        try {
            $jwt->validateToken('only.two.parts.four');
            $this->fail('Should have thrown exception');
        } catch (\InvalidArgumentException $e) {
            $this->assertEquals('Invalid token.', $e->getMessage());
        }
        
        // Test 3: Token with empty signature
        try {
            $jwt->validateToken('header.payload.');
            $this->fail('Should have thrown exception');
        } catch (\InvalidArgumentException $e) {
            $this->assertEquals('Invalid token.', $e->getMessage());
        }
        
        $this->assertTrue(true); // All generic error messages verified
    }
    
    public function testIatTooFarInFutureThrowsException(): void
    {
        $jwt = new JwToken('this-is-a-secure-32-byte-secret-key-for-testing');
        
        $payload = [
            'user_id' => 1,
            'iat' => time() + 315360001 // Over MAX_TIMESTAMP_OFFSET
        ];
        
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('iat timestamp is too far in the future');
        $jwt->createToken($payload);
    }
    
    public function testIatBeforeYear2000ThrowsException(): void
    {
        $jwt = new JwToken('this-is-a-secure-32-byte-secret-key-for-testing');
        
        $payload = [
            'user_id' => 1,
            'iat' => 946684799 // 1 second before 2000-01-01
        ];
        
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('iat timestamp is invalid');
        $jwt->createToken($payload);
    }
    
    public function testNbfTooFarInFutureThrowsException(): void
    {
        $jwt = new JwToken('this-is-a-secure-32-byte-secret-key-for-testing');
        
        $payload = [
            'user_id' => 1,
            'nbf' => time() + 315360001 // Over MAX_TIMESTAMP_OFFSET
        ];
        
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('nbf timestamp is too far in the future');
        $jwt->createToken($payload);
    }
    
    public function testNbfBeforeYear2000ThrowsException(): void
    {
        $jwt = new JwToken('this-is-a-secure-32-byte-secret-key-for-testing');
        
        $payload = [
            'user_id' => 1,
            'nbf' => 946684799 // 1 second before 2000-01-01
        ];
        
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('nbf timestamp is invalid');
        $jwt->createToken($payload);
    }
    
    public function testNonIntegerIatThrowsException(): void
    {
        $jwt = new JwToken('this-is-a-secure-32-byte-secret-key-for-testing');
        
        $payload = [
            'user_id' => 1,
            'iat' => '1234567890' // String instead of int
        ];
        
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Claim iat must be an integer timestamp');
        $jwt->createToken($payload);
    }
    
    public function testNonIntegerNbfThrowsException(): void
    {
        $jwt = new JwToken('this-is-a-secure-32-byte-secret-key-for-testing');
        
        $payload = [
            'user_id' => 1,
            'nbf' => '1234567890' // String instead of int
        ];
        
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Claim nbf must be an integer timestamp');
        $jwt->createToken($payload);
    }
}
