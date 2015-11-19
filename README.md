# EasyRSA

Simple and Secure Wrapper for PHPSecLib

## Motivation

Although the long-term security of RSA is questionable (at best) given the
advances in index calculus attacks, there are many issues with how RSA is
implemented in popular PHP cryptography libraries that make it vulnerable to
attacks *today*.

Thanks to the folks who developed [PHPSecLib](https://github.com/phpseclib/phpseclib),
it's possible to use secure RSA in PHP. However, it's not user-friendly enough
for the average PHP developer to use to its full potential. So we took it upon
ourselves to offer a user-friendly interface instead.

## How to use this library?

### Generating RSA key pairs

You can generate 2048-bit keys (or larger) using EasyRSA. The default size is 2048.

```php
use \ParagonIE\EasyRSA\EasyRSA;

list($secretKey, $publicKey) = EasyRSA::generateKeyPair(4096);
```

### Encrypting/Decrypting a Message

```php
$ciphertext = EasyRSA::encrypt($message, $publicKey);

$plaintext = EasyRSA::decrypt($ciphertext, $secretKey);
```

### Signing/Verifying a Message

```php
$signature = EasyRSA::sign($message, $secretKey);

if (EasyRSA::verify($message, $signature, $publicKey)) {
    // Signature is valid!
}
```

## What Does it Do Under the Hood?

* Encryption
    * Generates an ephemeral encryption key
    * Encrypts your plaintext message using [defuse/php-encryption](https://github.com/defuse/php-encryption)
      (authenticated symmetric-key encryption)
    * Encrypts the ephemeral key with your RSA public key, using PHPSecLib
      (RSAES-OAEP + MGF1-SHA256)
    * Calculates a checksum of both encrypted values (and a version tag)
* Authentication
    * Signs a message using PHPSecLib (RSASS-PSS + MGF1-SHA256)
