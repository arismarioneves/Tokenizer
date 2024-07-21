<?php

/**
 *  ▓▓▓▓Dev by Mari05liM▓▓▓▓
 *  Mari05liM
 *  mariodev@outlook.com.br
 *
 *  Criptografia: 1.0
 **/

define('VERSAO', '1.0'); // Versão Tokenizer

// Parâmetros
// Valor: Valor a ser criptografado
// Chave: Chave de criptografia
// Validade: true = 1 dia, false = quando a versão mudar

// Criptografar parâmetro
function criptografar($valor, $chave = 'AE8', $validade = TRUE)
{
    // Define um token de validade
    $token = ($validade ? date('Y-m-d') . VERSAO : VERSAO);
    // Gera um hash com o token e a chave
    $hash = hash_hmac('sha256', $token, $chave);
    // Cria um vetor de inicialização
    $iv = substr($hash, 0, 16);
    // Criptografa o valor
    $criptografado = openssl_encrypt($valor, 'AES-256-CBC', $hash, 0, $iv);

    // Retorne o valor criptografado
    return encodeBase64($criptografado);
}

// Descriptografar parâmetro
function descriptografar($valor, $chave = 'AE8', $validade = TRUE)
{
    // Decodifica o valor
    $valor = decodeBase64($valor);
    // Define um token de validade
    $token = ($validade ? date('Y-m-d') . VERSAO : VERSAO);
    // Gera um hash com o token e a chave
    $hash = hash_hmac('sha256', $token, $chave);
    // Cria um vetor de inicialização
    $iv = substr($hash, 0, 16);
    // Descriptografa o valor
    $descriptografado = openssl_decrypt($valor, 'AES-256-CBC', $hash, 0, $iv);
    // Verifica se o token é válido
    if ($descriptografado === false) {
        return false;
    }

    // Retorna o valor descriptografado
    return $descriptografado;
}

// Codifica base64
function encodeBase64($base64)
{
    $encoded = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($base64));
    $encoded = rtrim($encoded, '-_');
    return $encoded;
}

// Decodifica base64
function decodeBase64($encoded)
{
    $decoded = str_replace(['-', '_'], ['+', '/'], $encoded);
    $decoded = str_pad($decoded, strlen($decoded) % 4, '=', STR_PAD_RIGHT);
    $decoded = base64_decode($decoded);
    return $decoded;
}

//---

echo criptografar('Tokenizer');
