<?php
namespace ParagonIE\EasyRSA;

use \phpseclib\Crypt\RSA;
// defuse/php-encryption:
use \Crypto;

class EasyRSA implements EasyRSAInterface
{
    const SEPARATOR = '$';
    const VERSION_TAG = "EzR1";
    
    /**
     * Generate a private/public RSA key pair
     * 
     * @return array [private, public]
     */
    public static function generateKeyPair($size = 2048)
    {
        if ($size < 2048) {
            throw new \Exception('Key size must be at least 2048 bits.');
        }
        $rsa = new RSA();
        $keypair = $rsa->createKey($size);
        return array(
            $keypair['privatekey'],
            $keypair['publickey']
        );
    }
    
    /**
     * Encrypt a message with defuse/php-encryption, using an ephemeral key, 
     * then encrypt the key with RSA.
     * 
     * @param string $plaintext
     * @param string $rsaPublicKey
     * 
     * @return string
     */
    public static function encrypt($plaintext, $rsaPublicKey)
    {
        // Random encryption key
        $ephemeral = Crypto::createNewRandomKey();
        
        // Encrypt the actual message
        $symmetric = \base64_encode(
            Crypto::encrypt($plaintext, $ephemeral)
        );
        
        // Use RSA to encrypt the encryption key
        $storeKey = \base64_encode(
            self::rsaEncrypt($ephemeral, $rsaPublicKey)
        );
        
        $packaged = \implode(self::SEPARATOR,
            array(
                self::VERSION_TAG,
                $storeKey,
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
     * 
     * Encrypt a message with defuse/php-encryption, using an ephemeral key, 
     * then encrypt the key with RSA.
     * 
     * @param string $ciphertext
     * @param string $rsaPrivateKey
     * 
     * @return string
     */
    public static function decrypt($ciphertext, $rsaPrivateKey)
    {
        $split = explode(self::SEPARATOR, $ciphertext);
        if (\count($split) !== 4) {
            throw new \Exception('Invalid ciphertext message');
        }
        if (!\hash_equals($split[0], self::VERSION_TAG)) {
            throw new \Exception('Invalid version tag');
        }
        $checksum = \substr(
            \hash('sha256', implode('$', array_slice($split, 0, 3))),
            0,
            16
        );
        if (!\hash_equals($split[3], $checksum)) {
            throw new \Exception('Invalid checksum');
        }
        
        $key = self::rsaDecrypt(
            \base64_decode($split[1]),
            $rsaPrivateKey
        );
        return Crypto::Decrypt(
            \base64_decode($split[2]),
            $key
        );
    }
    
    /**
     * Sign with RSASS-PSS + MGF1+SHA256
     * 
     * @param string $message
     * @param string $rsaPrivateKey
     * @return string
     */
    public static function sign($message, $rsaPrivateKey)
    {
        $rsa = new RSA();
        $rsa->setSignatureMode(RSA::SIGNATURE_PSS);
        $rsa->setMGFHash('sha256');
        
        $rsa->loadKey($rsaPrivateKey);
        return $rsa->sign($message);
    }
    
    /**
     * Verify with RSASS-PSS + MGF1+SHA256
     * 
     * @param string $message
     * @param string $signature
     * @param string $rsaPublicKey
     * @return bool
     */
    public static function verify($message, $signature, $rsaPublicKey)
    {
        $rsa = new RSA();
        $rsa->setSignatureMode(RSA::SIGNATURE_PSS);
        $rsa->setMGFHash('sha256');
        
        $rsa->loadKey($rsaPublicKey);
        return $rsa->verify($message, $signature);
    }
    
    /**
     * Decrypt with RSAES-OAEP + MGF1+SHA256
     * 
     * @param string $plaintext
     * @param string $rsaPublicKey
     * @return string
     */
    protected static function rsaEncrypt($plaintext, $rsaPublicKey)
    {
        $rsa = new RSA();
        $rsa->setEncryptionMode(RSA::ENCRYPTION_OAEP);
        $rsa->setMGFHash('sha256');
        
        $rsa->loadKey($rsaPublicKey);
        return $rsa->encrypt($plaintext);
    }
    
    /**
     * Decrypt with RSAES-OAEP + MGF1+SHA256
     * 
     * @param string $ciphertext
     * @param string $rsaPrivateKey
     * @return string
     */
    protected static function rsaDecrypt($ciphertext, $rsaPrivateKey)
    {
        $rsa = new RSA();
        $rsa->setEncryptionMode(RSA::ENCRYPTION_OAEP);
        $rsa->setMGFHash('sha256');
        
        $rsa->loadKey($rsaPrivateKey);
        return $rsa->decrypt($ciphertext);
    }
}
