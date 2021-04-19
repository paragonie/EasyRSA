<?php
namespace ParagonIE\EasyRSA;

use Defuse\Crypto\Key;

/**
 * Class Kludge
 * @package ParagonIE\EasyRSA
 */
class Kludge
{
    /**
     * Use an internally generated key in a Defuse context
     *
     * @param string $randomBytes
     * @return Key
     * @psalm-suppress MissingClosureParamType
     * @psalm-suppress MissingClosureReturnType
     * @psalm-suppress PossiblyInvalidFunctionCall
     */
    public function defuseKey($randomBytes)
    {
        $key = Key::createNewRandomKey();
        $func = function ($bytes) {
            /** @psalm-suppress UndefinedThisPropertyAssignment */
            $this->key_bytes = $bytes;
        };
        $helper = $func->bindTo($key, $key);
        $helper($randomBytes);
        return $key;
    }
}