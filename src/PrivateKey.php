<?php
namespace ParagonIE\EasyRSA;


class PrivateKey
{
    protected $keyMaterial = '';

    /**
     * PrivateKey constructor.
     * @param $string
     */
    public function __construct($string)
    {
        $this->keyMaterial = $string;
    }

    /**
     * @return array
     */
    public function __debugInfo()
    {
        return [];
    }

    /**
     * return PublicKey
     */
    public function getPublicKey()
    {
        $res = \openssl_pkey_get_private($this->keyMaterial);
        $pubkey = \openssl_pkey_get_details($res);
        $public = \rtrim(
            \str_replace("\n", "\r\n", $pubkey['key']),
            "\r\n"
        );
        return new PublicKey($public);
    }

    /**
     * @return string
     */
    public function getKey()
    {
        return $this->keyMaterial;
    }
}