<?php

/**
 *  ▓▓▓▓Dev by Mari05liM▓▓▓▓
 *  Mari05liM
 *  mariodev@outlook.com.br
 **/

namespace AE8\Tokenizer;

class Tokenizer
{
    const VERSAO = '2.1';

    public static function criptografar($valor, $chave = 'AE8', $validade = false)
    {
        date_default_timezone_set('America/Sao_Paulo');

        if (!$valor) {
            return false;
        }

        $versao = str_replace('.', '', self::VERSAO);
        $data = $validade ? date('ymd') : '';
        $dados = json_encode(['1' => $valor, '2' => $validade ? 1 : 0, '3' => $versao, '4' => $data]);
        $chaveSegura = self::derivarChave($chave, $versao);
        $iv = openssl_random_pseudo_bytes(16);
        $criptografado = openssl_encrypt($dados, 'AES-256-CBC', $chaveSegura, 0, $iv);

        if ($criptografado === false) {
            return false;
        }

        return self::encodeBase64($iv . $criptografado);
    }

    public static function descriptografar($valor, $chave = 'AE8')
    {
        date_default_timezone_set('America/Sao_Paulo');

        if (!$valor) {
            return false;
        }

        $versao = str_replace('.', '', self::VERSAO);
        $valorDecodificado = self::decodeBase64($valor);
        $iv = substr($valorDecodificado, 0, 16);
        $criptografado = substr($valorDecodificado, 16);
        $chaveSegura = self::derivarChave($chave, $versao);
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

    private static function derivarChave($chave, $token)
    {
        return hash_pbkdf2('sha256', $chave, $token, 1000, 32, true);
    }

    private static function encodeBase64($data)
    {
        $encoded = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($data));
        return rtrim($encoded, '-_');
    }

    private static function decodeBase64($data)
    {
        $decoded = str_replace(['-', '_'], ['+', '/'], $data);
        $decoded = str_pad($decoded, strlen($decoded) % 4, '=', STR_PAD_RIGHT);
        return base64_decode($decoded);
    }
}
