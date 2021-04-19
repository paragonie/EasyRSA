<?php
namespace ParagonIE\EasyRSA;

interface EasyRSAInterface 
{
    /**
     * @param string $plaintext
     * @param PublicKey $rsaPublicKey
     * @return string
     */
    public static function encrypt($plaintext, PublicKey $rsaPublicKey);

    /**
     * @param string $ciphertext
     * @param PrivateKey $rsaPrivateKey
     * @return string
     */
    public static function decrypt($ciphertext, PrivateKey $rsaPrivateKey);

    /**
     * @param string $message
     * @param PrivateKey $rsaPrivateKey
     * @return string
     */
    public static function sign($message, PrivateKey $rsaPrivateKey);

    /**
     * @param string $message
     * @param string $signature
     * @param PublicKey $rsaPublicKey
     * @return bool
     */
    public static function verify($message, $signature, PublicKey $rsaPublicKey);
}
