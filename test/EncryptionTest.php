<?php
use \ParagonIE\EasyRSA\EasyRSA;

class EncryptionTest extends PHPUnit_Framework_TestCase
{
    public function testEncrypt()
    {
        list($secretKey, $publicKey) = EasyRSA::generateKeyPair(2048);
        
        $plain = str_repeat(
            'This is a relatively long plaintext message, far longer than RSA could safely encrypt directly.' . "\n",
            256
        );
        $encrypt = EasyRSA::encrypt($plain, $publicKey);
        $decrypt = EasyRSA::decrypt($encrypt, $secretKey);
        
        $this->assertTrue($decrypt === $plain);
    }
}