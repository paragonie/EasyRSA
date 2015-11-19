<?php
use \ParagonIE\EasyRSA\EasyRSA;

class SignatureTest extends PHPUnit_Framework_TestCase
{
    public function testEncrypt()
    {
        list($secretKey, $publicKey) = EasyRSA::generateKeyPair(2048);
        
        $plain = 'This is a message.';
        $signature = EasyRSA::sign($plain, $secretKey);
        
        $this->assertTrue(EasyRSA::verify($plain, $signature, $publicKey));
    }
}