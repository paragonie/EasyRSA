# EasyRSA

[![Build Status](https://travis-ci.org/paragonie/EasyRSA.svg?branch=master)](https://travis-ci.org/paragonie/EasyRSA)

Simple and Secure Wrapper for [phpseclib](https://github.com/phpseclib/phpseclib).

## Important!

For better security, you want to use [libsodium](https://pecl.php.net/package/libsodium), not EasyRSA.

## Motivation

Although the long-term security of RSA is questionable (at best) given the
advances in index calculus attacks, there are many issues with how RSA is
implemented in popular PHP cryptography libraries that make it vulnerable to
attacks *today*.

Thanks to the folks who developed [phpseclib](https://github.com/phpseclib/phpseclib),
it's possible to use secure RSA in PHP. However, it's not user-friendly enough
for the average PHP developer to use to its full potential. So we took it upon
ourselves to offer a user-friendly interface instead.

EasyRSA is MIT licensed and brought to you by the secure PHP development team at
[Paragon Initiative Enterprises](https://paragonie.com).

## How to use this library?
`composer require paragonie/easyrsa`

### Generating RSA key pairs

You can generate 2048-bit keys (or larger) using EasyRSA. The default size is 2048.

```php
<?php
use ParagonIE\EasyRSA\KeyPair;

$keyPair = KeyPair::generateKeyPair(4096);

$secretKey = $keyPair->getPrivateKey();
$publicKey = $keyPair->getPublicKey();
```

#### Getting the Raw Key

```php
<?php
/** @var \ParagonIE\EasyRSA\PublicKey $publicKey */
var_dump($publicKey->getKey());
```

### Encrypting/Decrypting a Message

```php
<?php
use ParagonIE\EasyRSA\EasyRSA;

$message = "test";
/** @var \ParagonIE\EasyRSA\PublicKey $publicKey */
/** @var \ParagonIE\EasyRSA\PrivateKey $secretKey */

$ciphertext = EasyRSA::encrypt($message, $publicKey);

$plaintext = EasyRSA::decrypt($ciphertext, $secretKey);
```

### Signing/Verifying a Message

```php
<?php
use ParagonIE\EasyRSA\EasyRSA;

$message = "test";
/** @var \ParagonIE\EasyRSA\PublicKey $publicKey */
/** @var \ParagonIE\EasyRSA\PrivateKey $secretKey */

$signature = EasyRSA::sign($message, $secretKey);

if (EasyRSA::verify($message, $signature, $publicKey)) {
    // Signature is valid!
}
```

## Compatibility

EasyRSA is only compatible with itself. It is not compatible with OpenGPG (GnuPG, Mailvelope, etc.) You'll want [GPG-Mailer](https://github.com/paragonie/gpg-mailer) instead.

## What Does it Do Under the Hood?

* Encryption (KEM+DEM)
    * Generates an random secret value
    * Encrypts the random secret value with your RSA public key, using PHPSecLib
      (RSAES-OAEP + MGF1-SHA256)
    * Derives an encryption key from the secret value and its RSA-encrypted ciphertext, 
      using HMAC-SHA256.
    * Encrypts your plaintext message using [defuse/php-encryption](https://github.com/defuse/php-encryption)
      (authenticated symmetric-key encryption)
    * Calculates a checksum of both encrypted values (and a version tag)
* Authentication
    * Signs a message using PHPSecLib (RSASS-PSS + MGF1-SHA256)

## Support Contracts

If your company uses this library in their products or services, you may be
interested in [purchasing a support contract from Paragon Initiative Enterprises](https://paragonie.com/enterprise).
