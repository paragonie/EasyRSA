<?php
namespace ParagonIE\EasyRSA;

use Defuse\Crypto\Key;

class Kludge
{
    /**
     * Use an internally generated key in a Defuse context
     *
     * @param string $randomBytes
     * @return Key
     */
    public function defuseKey($randomBytes)
    {
        $key = Key::createNewRandomKey();
        $func = function ($bytes) {
            $this->key_bytes = $bytes;
        };
        $helper = $func->bindTo($key, $key);
        $helper($randomBytes);
        return $key;
    }
}