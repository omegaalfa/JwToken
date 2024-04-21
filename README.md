# JwToken

Esta biblioteca fornece uma implementação simples de JWT (JSON Web Token) em PHP. Ela permite criar, validar e decodificar tokens JWT com base em uma chave secreta.

## Instalação

Você pode instalar esta biblioteca usando o Composer:

```bash
composer require omegalfa/jwtoken
```
Descrição
-----------

Essa classe `JwToken` é uma implementação em PHP para gerar e validar tokens JWT (JSON Web Tokens). Ela permite criar tokens seguros e válidos, além de verificar a autenticidade de tokens recebidos.

Características
--------------

*   Geração de tokens JWT com payload personalizado
*   Validação de tokens JWT com chave secreta
*   Decodificação de tokens JWT para obter o payload original

Exemplo de uso
---------------

```php
use omegalfa\jwtoken\JwToken;

$secretKey = 'your_secret_key_here';
$jwToken = new JwToken($secretKey);

$payload = ['name' => 'John Doe', 'email' => 'john.doe@example.com'];
$token = $jwToken->createToken($payload);

echo $token; // Output: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaGFuIjoiRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c

$isValid = $jwToken->validateToken($token);
echo $isValid ? 'Token is valid' : 'Token is invalid'; // Output: Token is valid

$decodedPayload = $jwToken->decodeToken($token);
print_r($decodedPayload); // Output: Array ( [name] => John Doe [email] => john.doe@example.com )
