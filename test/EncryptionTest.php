<?php
use \ParagonIE\ConstantTime\Base64;
use \ParagonIE\EasyRSA\EasyRSA;
use \ParagonIE\EasyRSA\KeyPair;

class EncryptionTest extends PHPUnit_Framework_TestCase
{
    public function testEncrypt()
    {
        $keyPair = KeyPair::generateKeyPair(2048);
            $secretKey = $keyPair->getPrivateKey();
            $publicKey = $keyPair->getPublicKey();
        
        $plain = str_repeat(
            'This is a relatively long plaintext message, far longer than RSA could safely encrypt directly.' . "\n",
            mt_rand(128, 512)
        );
        $encrypt = EasyRSA::encrypt($plain, $publicKey);
        $decrypt = EasyRSA::decrypt($encrypt, $secretKey);
        
        $dissect = explode('$', $encrypt);
        $this->assertEquals(EasyRSA::VERSION_TAG, $dissect[0]);
        $this->assertEquals($decrypt, $plain);
        
        $size = strlen($plain);
            $size += 4;  // Header
            $size += 16; // IV
            $size += 32; // HHKF Salt
            $size += 32; // HMAC
        $this->assertEquals(
            strlen(Base64::decode($dissect[2])),
            $size
        );
    }
    
    public function testFailure()
    {
        try {
            KeyPair::generateKeyPair(1024);
            $this->fail('Accepts too small of a key size!');
            return;
        } catch (\Exception $ex) {
            $keyPair = KeyPair::generateKeyPair(2048);
        }
        $secretKey = $keyPair->getPrivateKey();
        $publicKey = $keyPair->getPublicKey();
        
        $plain = 'Short Message';
        $encrypt = EasyRSA::encrypt($plain, $publicKey);
        
        $dissect = explode('$', $encrypt);
        // Flip a bit in the key, randomly!
        $dissect[1] = base64_decode($dissect[1]);
        
        $l = mt_rand(0, strlen($dissect[1]) - 1);
        $dissect[1][$l] = \chr(
            \ord($dissect[1][$l]) ^ (1 << mt_rand(0, 7))
        );
        $dissect[1] = base64_encode($dissect[1]);
        try {
            EasyRSA::decrypt(implode('$', $dissect), $secretKey);
            $this->fail('Checksum collision or logic error.');
            return;
        } catch (\Exception $ex) {
            $this->assertInstanceOf('\ParagonIE\EasyRSA\Exception\InvalidChecksumException', $ex);
        }
        $dissect[3] = substr(
            hash('sha256', implode('$', array_slice($dissect, 0, 3))),
            0,
            16
        );
        
        try {
            EasyRSA::decrypt(implode('$', $dissect), $secretKey);
            $this->fail('This should not have passed.');
        } catch (\Exception $ex) {
            $this->assertInstanceOf('\ParagonIE\EasyRSA\Exception\InvalidCiphertextException', $ex);
        }
        
        ///////////////////////////////////////////////////////////////////////
        
        $dissect = explode('$', $encrypt);
        
        // Flip a bit in the message, randomly!
        $dissect[2] = base64_decode($dissect[2]);
        $l = mt_rand(0, strlen($dissect[2]) - 1);
        $dissect[2][$l] = \chr(
            \ord($dissect[2][$l]) ^ (1 << mt_rand(0, 7))
        );
        $dissect[2] = Base64::encode($dissect[2]);
        try {
            $dummy = EasyRSA::decrypt(implode('$', $dissect), $secretKey);
            $this->fail('Checksum collision or logic error.');
            unset($dummy);
            return;
        } catch (\Exception $ex) {
            $this->assertInstanceOf('\ParagonIE\EasyRSA\Exception\InvalidChecksumException', $ex);
        }
        $dissect[3] = substr(
            hash('sha256', implode('$', array_slice($dissect, 0, 3))),
            0,
            16
        );

        try {
            EasyRSA::decrypt(implode('$', $dissect), $secretKey);
            $this->fail('This should not have passed.');
        } catch (\Exception $ex) {
            $this->assertInstanceOf('\Defuse\Crypto\Exception\WrongKeyOrModifiedCiphertextException', $ex);
        }
    }
}
