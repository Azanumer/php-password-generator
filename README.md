# PHP Password Generator

A dependency-free secure password and passphrase generator — `random_int()` (CSPRNG) throughout, no modulo bias, no `mt_rand()`.

## Usage

```php
require_once 'src/PasswordGenerator.php';

use Azanumer\PasswordGenerator;

$gen = new PasswordGenerator();

// 16 chars, mixed case + digits + symbols (~100 bits of entropy)
$gen->generate(16);

// Letters + digits only — easier to read out over the phone
$gen->generate(20, array('symbols' => false));

// Memorable passphrase
$gen->passphrase(4);          // e.g. "correct-horse-battery-staple"
$gen->passphrase(6, '-', true); // 6 words + a random 2-digit number

// Numeric PIN
$gen->generatePin(6);         // e.g. "482917"
```

## Features

- **Guaranteed coverage**: every generated password contains at least one character from each enabled set, then a Fisher–Yates shuffle (driven by `random_int()`) hides which positions those are.
- **Ambiguous characters excluded by default**: `l`, `I`, `1`, `O`, `0` are left out so passwords survive being read aloud or typed from a screenshot. Pass `'ambiguous' => true` to include them.
- **Entropy estimates**: `entropyBits($length)` for passwords and `passphraseEntropyBits($words)` for passphrases, so you can enforce a real strength policy instead of guessing.
- **Passphrases**: built-in 128-word list (4 words ≈ 28 bits, 6 words ≈ 42 bits). For production, load the EFF large wordlist (7,776 words) with `setWordlist()` — 4 words then give ~52 bits.

## Requirements

- PHP 7.0+ (`random_int()` is core since PHP 7.0)

## License

MIT — see [LICENSE](LICENSE).
