<?php
use ParagonIE\EasyRSA\EasyRSA;
use ParagonIE\EasyRSA\KeyPair;
use PHPUnit\Framework\TestCase;

class SignatureTest extends TestCase
{
    public function testSign()
    {
        $keyPair = KeyPair::generateKeyPair(2048);
            $secretKey = $keyPair->getPrivateKey();
            $publicKey = $keyPair->getPublicKey();
        
        $plain = 'This is a message.';
        $signature = EasyRSA::sign($plain, $secretKey);
        
        $this->assertTrue(EasyRSA::verify($plain, $signature, $publicKey));
    }
}