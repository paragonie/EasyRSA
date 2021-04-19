<?php
namespace ParagonIE\EasyRSA;

class PublicKey
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
     * @return string
     */
    public function getKey()
    {
        return $this->keyMaterial;
    }
}
