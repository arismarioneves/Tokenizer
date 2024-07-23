<?php

/**
 *  ▓▓▓▓Dev by Mari05liM▓▓▓▓
 *  Mari05liM
 *  mariodev@outlook.com.br
 *
 *  Criptografia: 1.5
 **/

namespace AE8\Tokenizer;

class Tokenizer
{
    const VERSAO = '1.5';

    public static function criptografar($valor, $chave = 'AE8', $validade = TRUE)
    {
        $token = ($validade ? date('Y-m-d') . self::VERSAO : self::VERSAO);
        $chaveSegura = self::derivarChave($chave, $token);
        $iv = openssl_random_pseudo_bytes(16);
        $criptografado = openssl_encrypt($valor, 'AES-256-CBC', $chaveSegura, 0, $iv);

        if ($criptografado === false) {
            return false;
        }

        return self::encodeBase64($iv . $criptografado);
    }

    public static function descriptografar($valor, $chave = 'AE8', $validade = TRUE)
    {
        $valorDecodificado = self::decodeBase64($valor);
        $iv = substr($valorDecodificado, 0, 16);
        $textoCriptografado = substr($valorDecodificado, 16);
        $token = ($validade ? date('Y-m-d') . self::VERSAO : self::VERSAO);
        $chaveSegura = self::derivarChave($chave, $token);
        $descriptografado = openssl_decrypt($textoCriptografado, 'AES-256-CBC', $chaveSegura, 0, $iv);

        if ($descriptografado === false) {
            return false;
        }

        return $descriptografado;
    }

    private static function derivarChave($chave, $token)
    {
        return hash_pbkdf2('sha256', $chave, $token, 1000, 32, true);
    }

    private static function encodeBase64($base64)
    {
        $encoded = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($base64));
        return rtrim($encoded, '-_');
    }

    private static function decodeBase64($encoded)
    {
        $decoded = str_replace(['-', '_'], ['+', '/'], $encoded);
        $decoded = str_pad($decoded, strlen($decoded) % 4, '=', STR_PAD_RIGHT);
        return base64_decode($decoded);
    }
}
