<?php

/**
 *  ▓▓▓▓Dev by Mari05liM▓▓▓▓
 *  Mari05liM
 *  mariodev@outlook.com.br
 **/

define('VERSAO', '2.1');

date_default_timezone_set('America/Sao_Paulo');

// Criptografar
function criptografar($valor, $chave = 'AE8', $validade = false)
{
    if (!$valor) {
        return false;
    }

    $versao = str_replace('.', '', VERSAO);
    $data = $validade ? date('ymd') : '';
    $dados = json_encode(['1' => $valor, '2' => $validade ? 1 : 0, '3' => $versao, '4' => $data]);
    $chaveSegura = derivarChave($chave, $versao);
    $iv = openssl_random_pseudo_bytes(16);
    $criptografado = openssl_encrypt($dados, 'AES-256-CBC', $chaveSegura, 0, $iv);

    return $criptografado === false ? false : encodeBase64($iv . $criptografado);
}

// Descriptografar
function descriptografar($valor, $chave = 'AE8')
{
    if (!$valor) {
        return false;
    }

    $versao = str_replace('.', '', VERSAO);
    $valorDecodificado = decodeBase64($valor);
    $iv = substr($valorDecodificado, 0, 16);
    $criptografado = substr($valorDecodificado, 16);
    $chaveSegura = derivarChave($chave, $versao);
    $dadosDescriptografados = openssl_decrypt($criptografado, 'AES-256-CBC', $chaveSegura, 0, $iv);

    if ($dadosDescriptografados === false) {
        return false;
    }

    $dados = json_decode($dadosDescriptografados, true);
    if (!$dados) {
        return false;
    }

    if ($dados['2'] && $dados['4'] !== date('ymd')) {
        return false;
    }

    return $dados['3'] === $versao ? $dados['1'] : false;
}

// Derivar chave
function derivarChave($chave, $token)
{
    return hash_pbkdf2('sha256', $chave, $token, 1000, 32, true);
}

// Codificar base64
function encodeBase64($data)
{
    $encoded = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($data));
    return rtrim($encoded, '-_');
}

// Decodificar base64
function decodeBase64($data)
{
    $decoded = str_replace(['-', '_'], ['+', '/'], $data);
    $decoded = str_pad($decoded, strlen($decoded) % 4, '=', STR_PAD_RIGHT);
    return base64_decode($decoded);
}

// Teste de criptografia e descriptografia
$encrypted = criptografar('Tokenizer', 'AE8', true);
echo "Encrypted: " . $encrypted . "\n";
$decrypted = descriptografar($encrypted, 'AE8');
echo "Decrypted: " . $decrypted . "\n";
