<?php
use ParagonIE\EasyRSA\KeyPair;
use PHPUnit\Framework\TestCase;

class KeyPairTest extends TestCase
{
    public function testBasicFunctions()
    {
        $kp = KeyPair::generateKeyPair(2048);
        $private = $kp->getPrivateKey();
        $public = $kp->getPublicKey();
        $this->assertEquals(
            $kp->getPublicKey()->getKey(),
            $public->getKey()
        );

        $this->assertEquals(
            $private->getPublicKey()->getKey(),
            $public->getKey()
        );

        $kp2 = new KeyPair($private);
        $this->assertEquals(
            $kp->getPublicKey()->getKey(),
            $kp2->getPublicKey()->getKey()
        );

        $this->assertEquals(
            $kp2->getPublicKey()->getKey(),
            $public->getKey()
        );
    }
}