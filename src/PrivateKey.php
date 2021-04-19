<?php
namespace ParagonIE\EasyRSA;

/**
 * Class PrivateKey
 * @package ParagonIE\EasyRSA
 */
class PrivateKey
{
    /** @var string $keyMaterial */
    protected $keyMaterial = '';

    /**
     * PrivateKey constructor.
     * @param string $string
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
     * @return PublicKey
     */
    public function getPublicKey()
    {
        $res = \openssl_pkey_get_private($this->keyMaterial);
        $pubkey = \openssl_pkey_get_details($res);
        $public = \rtrim(
            \str_replace("\n", "\r\n", (string) $pubkey['key']),
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