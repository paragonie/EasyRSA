<?php
namespace ParagonIE\EasyRSA;

class PublicKey
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
     * @return string
     */
    public function getKey()
    {
        return $this->keyMaterial;
    }
}
