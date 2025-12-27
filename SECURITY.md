# Política de segurança

Este projeto prioriza a correção rápida de vulnerabilidades relacionadas a tokens JWT, chaves e enigmas criptográficos. Abaixo estão os detalhes de suporte e o fluxo ideal para reportar problemas.

## Versões suportadas

As versões com correções de segurança ativas são:

| Versão | Suporte ativo |
| --- | --- |
| `main` (branch principal) | ✅ |
| `1.x` (releases compatíveis com PHP 8.4+) | ✅ |
| versões anteriores | ❌ (sem correções) |

Se você utiliza um release antigo, considere atualizar para aproveitar as correções e melhorias de criptografia.

## Como reportar uma vulnerabilidade

1. Crie uma issue privada no GitHub usando o template de segurança se disponível.
2. Caso prefira, envie um e-mail para security@omegaalfa.dev com:
   - Descrição completa do cenário e do impacto (token forjado, assinatura inválida, etc.).
   - Passos mínimos para reproduzir, incluindo comandos `php`/`openssl` quando aplicável.
   - Versão do PHP (8.4+) e a branch ou tag do `JwToken` utilizada.
3. Se puder, inclua PoC (ex.: script PHP + token) para acelerar a triagem.

## O que esperar

- 📩 Confirmamos o recebimento em até 24 horas úteis.
- 🛡️ Solicitamos mais informações quando necessário e mantemos você atualizado a cada 2–3 dias durante a investigação.
- 📦 Publicamos correções em menor tempo possível e avisamos pela issue ou e-mail usado no contato inicial.
- Se não houver feedback em 7 dias, revisaremos a prioridade e comunicaremos o status atual.

## Boas práticas para comunicadores

- Não compartilhe detalhes públicos enquanto não houver correção ou aviso oficial.
- Inclua o nível de urgência ou classificação (ex.: alta se um token ilimitado pode ser forjado).
- Informe se a vulnerabilidade também afeta integrações HMAC e RS256, especialmente rotinas de rotação de chaves.

Obrigado por ajudar a manter o JwToken seguro. Trabalhamos juntos para proteger fluxos críticos de autenticação.# Security Policy

## Supported Versions

Use this section to tell people about which versions of your project are
currently being supported with security updates.

| Version | Supported          |
| ------- | ------------------ |
| 5.1.x   | :white_check_mark: |
| 5.0.x   | :x:                |
| 4.0.x   | :white_check_mark: |
| < 4.0   | :x:                |

## Reporting a Vulnerability

Use this section to tell people how to report a vulnerability.

Tell them where to go, how often they can expect to get an update on a
reported vulnerability, what to expect if the vulnerability is accepted or
declined, etc.
