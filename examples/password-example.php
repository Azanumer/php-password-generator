<?php
/**
 * PasswordGenerator demo — run: php examples/password-example.php
 */

require_once __DIR__ . '/../src/PasswordGenerator.php';

use Azanumer\PasswordGenerator;

$gen = new PasswordGenerator();

// Default: 16 characters, mixed case + digits + symbols, ambiguous chars excluded.
$password = $gen->generate(16);
echo "Password (16):        {$password}\n";
echo "Entropy:              {$gen->entropyBits(16)} bits\n\n";

// Letters + digits only, 20 chars — easier to type over the phone.
echo "Password (letters+digits, 20): {$gen->generate(20, array('symbols' => false))}\n\n";

// Memorable passphrase — 6 words ≈ 42 bits with the built-in 128-word list.
// For production use, load the EFF large wordlist (7,776 words) via setWordlist()
// and 4 words then give ~52 bits.
echo "Passphrase (6 words): {$gen->passphrase(6)}\n";
echo "Passphrase entropy:   {$gen->passphraseEntropyBits(6)} bits\n\n";

// Numeric PIN for a door code / 2FA backup.
echo "PIN (6 digits):       {$gen->generatePin(6)}\n";
