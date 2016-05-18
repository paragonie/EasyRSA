<?php
namespace ParagonIE\EasyRSA;

interface EasyRSAInterface 
{
    public static function encrypt($plaintext, PublicKey $rsaPublicKey);
    public static function decrypt($ciphertext, PrivateKey $rsaPrivateKey);
    public static function sign($plaintext, PrivateKey $rsaPrivateKey);
    public static function verify($ciphertext, $signature, PublicKey $rsaPublicKey);
}
