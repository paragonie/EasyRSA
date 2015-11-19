<?php
namespace ParagonIE\EasyRSA;

interface EasyRSAInterface 
{
    public static function generateKeyPair();
    public static function encrypt($plaintext, $rsaPublicKey);
    public static function decrypt($ciphertext, $rsaPrivateKey);
    public static function sign($plaintext, $rsaPrivateKey);
    public static function verify($ciphertext, $signature, $rsaPublicKey);
}
