<?php
namespace ParagonIE\EasyRSA;

use \phpseclib\Crypt\RSA;
use \ParagonIE\EasyRSA\Exception\InvalidKeyException;

class KeyPair
{
    private $privateKey;
    protected $publicKey;

    public function __construct(PrivateKey $privateKey, PublicKey $publicKey = null)
    {
        $this->privateKey = $privateKey;
        if (!$publicKey) {
            $publicKey = $this->privateKey->getPublicKey();
        }
        $this->publicKey = $publicKey;
    }

    /**
     * Generate a private/public RSA key pair
     *
     * @param int $size Key size
     * @param string $passphrase Optional - password-protected private key
     *
     * @return self
     * @throws InvalidKeyException
     */
    public static function generateKeyPair($size = 2048)
    {
        if ($size < 2048) {
            throw new InvalidKeyException('Key size must be at least 2048 bits.');
        }
        $rsa = new RSA();
        $keypair = $rsa->createKey($size);
        return new KeyPair(
            new PrivateKey($keypair['privatekey']),
            new PublicKey($keypair['publickey'])
        );
    }

    /**
     * @return PublicKey
     */
    public function getPublicKey()
    {
        return $this->publicKey;
    }

    /**
     * @return PrivateKey
     */
    public function getPrivateKey()
    {
        return $this->privateKey;
    }
}