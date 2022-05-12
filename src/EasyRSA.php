<?php
namespace ParagonIE\EasyRSA;

use ParagonIE\ConstantTime\Base64;
// PHPSecLib:
use phpseclib\Crypt\RSA;
// defuse/php-encryption:
use Defuse\Crypto\Key;
use Defuse\Crypto\Crypto;
use Defuse\Crypto\Exception\EnvironmentIsBrokenException;
use Defuse\Crypto\Exception\WrongKeyOrModifiedCiphertextException;
// Typed Exceptions:
use ParagonIE\EasyRSA\Exception\EasyRSAException;
use ParagonIE\EasyRSA\Exception\InvalidKeyException;
use ParagonIE\EasyRSA\Exception\InvalidChecksumException;
use ParagonIE\EasyRSA\Exception\InvalidCiphertextException;
use Exception;

/**
 * Class EasyRSA
 * @package ParagonIE\EasyRSA
 */
class EasyRSA implements EasyRSAInterface
{
    const SEPARATOR = '$';
    const VERSION_TAG = "EzR2";

    /** @var ?RSA $rsa */
    static private $rsa;

    /**
     * Set RSA to use in between calls
     *
     * @param RSA|null $rsa
     * @return void
     */
    public static function setRsa(RSA $rsa = null)
    {
        self::$rsa = $rsa;
    }

    /**
     * Get RSA
     *
     * @param int $mode
     *
     * @return RSA
     */
    public static function getRsa($mode)
    {
        /** @var RSA $rsa */
        if (!\is_null(self::$rsa)) {
            $rsa = self::$rsa;
        } else {
            $rsa = new RSA();
            $rsa->setMGFHash('sha256');
        }

        $rsa->setSignatureMode($mode);

        return $rsa;
    }

    /**
     * KEM+DEM approach to RSA encryption.
     *
     * @param string $plaintext
     * @param PublicKey $rsaPublicKey
     *
     * @return string
     *
     * @throws EasyRSAException
     * @throws EnvironmentIsBrokenException
     * @throws InvalidCiphertextException
     * @throws InvalidKeyException
     */
    public static function encrypt($plaintext, PublicKey $rsaPublicKey)
    {
        // Random encryption key
        try {
            $random_key = \random_bytes(32);
        } catch (Exception $ex) {
            throw new EasyRSAException("Could not generate one-time key", 0, $ex);
        }

        // Use RSA to encrypt the random key
        $rsaOut = self::rsaEncrypt($random_key, $rsaPublicKey);

        // Generate a symmetric key from the RSA output and plaintext
        $symmetricKey = \hash_hmac(
            'sha256',
            $rsaOut,
            $random_key,
            true
        );
        $ephemeral = self::defuseKey(
            $symmetricKey
        );

        // Now we encrypt the actual message
        $symmetric = Base64::encode(
            Crypto::encrypt($plaintext, $ephemeral, true)
        );

        $packaged = \implode(self::SEPARATOR,
            array(
                self::VERSION_TAG,
                Base64::encode($rsaOut),
                $symmetric
            )
        );

        $checksum = \substr(
            \hash('sha256', $packaged),
            0,
            16
        );

        // Return the ciphertext
        return $packaged . self::SEPARATOR . $checksum;
    }

    /**
     * KEM+DEM approach to RSA encryption.
     *
     * @param string $ciphertext
     * @param PrivateKey $rsaPrivateKey
     * @return string
     *
     * @throws EnvironmentIsBrokenException
     * @throws InvalidCiphertextException
     * @throws InvalidChecksumException
     * @throws WrongKeyOrModifiedCiphertextException
     *
     * @psalm-suppress MixedArgumentTypeCoercion
     */
    public static function decrypt($ciphertext, PrivateKey $rsaPrivateKey)
    {
        $split = \explode(self::SEPARATOR, $ciphertext);
        if (\count($split) !== 4) {
            throw new InvalidCiphertextException('Invalid ciphertext message');
        }
        if (!\hash_equals($split[0], self::VERSION_TAG)) {
            throw new InvalidCiphertextException('Invalid version tag');
        }
        $checksum = \substr(
            \hash('sha256', implode('$', array_slice($split, 0, 3))),
            0,
            16
        );
        if (!\hash_equals($split[3], $checksum)) {
            throw new InvalidChecksumException('Invalid checksum');
        }

        $rsaCipher = Base64::decode($split[1]);
        $rsaPlain = self::rsaDecrypt(
            $rsaCipher,
            $rsaPrivateKey
        );
        $symmetricKey = hash_hmac(
            'sha256',
            $rsaCipher,
            $rsaPlain,
            true
        );

        $key = self::defuseKey($symmetricKey);
        return Crypto::decrypt(
            Base64::decode($split[2]),
            $key,
            true
        );
    }

    /**
     * Sign with RSASSA-PSS + MGF1+SHA256
     *
     * @param string $message
     * @param PrivateKey $rsaPrivateKey
     * @return string
     *
     * @throws EasyRSAException
     * @throws InvalidKeyException
     */
    public static function sign($message, PrivateKey $rsaPrivateKey)
    {
        $rsa = self::getRsa(RSA::SIGNATURE_PSS);

        $loaded = $rsa->loadKey($rsaPrivateKey->getKey());
        if (!$loaded) {
            throw new InvalidKeyException('Signing failed due to invalid key');
        }

        $signed = $rsa->sign($message);
        if (!\is_string($signed)) {
            throw new EasyRSAException('RSA Encryption failed');
        }
        return $signed;
    }

    /**
     * Verify with RSASS-PSS + MGF1+SHA256
     *
     * @param string $message
     * @param string $signature
     * @param PublicKey $rsaPublicKey
     * @return bool
     *
     * @throws InvalidKeyException
     */
    public static function verify($message, $signature, PublicKey $rsaPublicKey)
    {
        $rsa = self::getRsa(RSA::SIGNATURE_PSS);

        $loaded = $rsa->loadKey($rsaPublicKey->getKey());
        if (!$loaded) {
            throw new InvalidKeyException('Verification failed due to invalid key');
        }

        return $rsa->verify($message, $signature);
    }

    /**
     * Decrypt with RSAES-OAEP + MGF1+SHA256
     *
     * @param string $plaintext
     * @param PublicKey $rsaPublicKey
     * @return string
     *
     * @throws EasyRSAException
     * @throws InvalidCiphertextException
     * @throws InvalidKeyException
     */
    protected static function rsaEncrypt($plaintext, PublicKey $rsaPublicKey)
    {
        $rsa = self::getRsa(RSA::ENCRYPTION_OAEP);

        $return = $rsa->loadKey($rsaPublicKey->getKey());
        if ($return === false) {
            throw new InvalidKeyException('Encryption failed due to invalid key');
        }

        $ciphertext = $rsa->encrypt($plaintext);
        if (!\is_string($ciphertext)) {
            throw new EasyRSAException('RSA Encryption failed');
        }
        return $ciphertext;
    }

    /**
     * Decrypt with RSAES-OAEP + MGF1+SHA256
     *
     * @param string $ciphertext
     * @param PrivateKey $rsaPrivateKey
     * @return string
     *
     * @throws InvalidCiphertextException
     * @throws InvalidKeyException
     */
    protected static function rsaDecrypt($ciphertext, PrivateKey $rsaPrivateKey)
    {
        $rsa = self::getRsa(RSA::ENCRYPTION_OAEP);

        $loaded = $rsa->loadKey($rsaPrivateKey->getKey());
        if (!$loaded) {
            throw new InvalidKeyException('Decryption failed due to invalid key');
        }

        $return = $rsa->decrypt($ciphertext);
        if (!\is_string($return)) {
            throw new InvalidCiphertextException('Decryption failed');
        }
        return $return;
    }

    /**
     * Use an internally generated key in a Defuse context
     *
     * @param string $randomBytes
     * @return Key
     */
    protected static function defuseKey($randomBytes)
    {
        $kludege = new Kludge();
        return $kludege->defuseKey($randomBytes);
    }
}
