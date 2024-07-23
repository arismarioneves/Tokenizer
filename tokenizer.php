<?php

/**
 *  ▓▓▓▓Dev by Mari05liM▓▓▓▓
 *  Mari05liM
 *  mariodev@outlook.com.br
 **/

define('VERSAO', '1.7'); // Versão Tokenizer

date_default_timezone_set('America/Sao_Paulo');

// Parâmetros
// Valor: Valor a ser criptografado
// Chave: Chave de criptografia
// Validade: true = 1 dia, false = quando a versão mudar

// Criptografar parâmetro
function criptografar($valor, $chave = 'AE8', $validade = false)
{
    // Define um token de validade
    $token = ($validade ? date('Y-m-d') . VERSAO : VERSAO);
    // Deriva uma chave segura usando a chave fornecida e o token
    $chaveSegura = derivarChave($chave, $token);
    // Gera um vetor de inicialização (IV) aleatório
    $iv = openssl_random_pseudo_bytes(16);
    // Criptografa o valor
    $criptografado = openssl_encrypt($valor, 'AES-256-CBC', $chaveSegura, 0, $iv);

    if ($criptografado === false) {
        return false;
    }

    // Codifica o IV e o texto criptografado em Base64
    $resultado = encodeBase64($iv . $criptografado);

    // Retorne o valor criptografado
    return $resultado;
}

// Descriptografar parâmetro
function descriptografar($valor, $chave = 'AE8', $validade = false)
{
    // Decodifica o valor
    $valorDecodificado = decodeBase64($valor);
    // Separa o IV do texto criptografado
    $iv = substr($valorDecodificado, 0, 16);
    $textoCriptografado = substr($valorDecodificado, 16);
    // Define um token de validade
    $token = ($validade ? date('Y-m-d') . VERSAO : VERSAO);
    // Deriva uma chave segura usando a chave fornecida e o token
    $chaveSegura = derivarChave($chave, $token);
    // Descriptografa o valor
    $descriptografado = openssl_decrypt($textoCriptografado, 'AES-256-CBC', $chaveSegura, 0, $iv);

    // Verifica se a descriptografia foi bem-sucedida
    if ($descriptografado === false) {
        return false;
    }

    // Retorna o valor descriptografado
    return $descriptografado;
}

// Função para derivar uma chave segura a partir da chave fornecida
function derivarChave($chave, $token)
{
    return hash_pbkdf2('sha256', $chave, $token, 1000, 32, true);
}

// Codifica base64
function encodeBase64($base64)
{
    $encoded = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($base64));
    return rtrim($encoded, '-_');
}

// Decodifica base64
function decodeBase64($encoded)
{
    $decoded = str_replace(['-', '_'], ['+', '/'], $encoded);
    $decoded = str_pad($decoded, strlen($decoded) % 4, '=', STR_PAD_RIGHT);
    return base64_decode($decoded);
}

//---

echo criptografar('Tokenizer');
