<?php
/**
 * PasswordGenerator — dependency-free secure password + passphrase generator.
 *
 * Uses random_int() (CSPRNG) throughout — no modulo bias, no mt_rand().
 *
 * Example:
 *   $gen = new PasswordGenerator();
 *   $gen->generate(16);                       // e.g. "k7#Qw9!zLp2@xRtY"
 *   $gen->passphrase(4);                      // e.g. "correct-horse-battery-staple"
 *   $gen->generatePin(6);                     // e.g. "482917"
 *   $gen->entropyBits(16);                    // estimated bits for a 16-char password
 *
 * @package Azanumer\PasswordGenerator
 */

namespace Azanumer;

class PasswordGenerator
{
    const LOWER   = 'abcdefghjkmnpqrstuvwxyz'; // ambiguous l, i, o removed
    const UPPER   = 'ABCDEFGHJKMNPQRSTUVWXYZ'; // ambiguous I, O removed
    const DIGITS  = '23456789';                // ambiguous 0, 1 removed
    const SYMBOLS = '!@#$%^&*()-_=+[]{};:,.?';

    /**
     * A compact diceware-style wordlist (128 common words) for passphrases.
     * Kept in-code so the class stays dependency-free; override via
     * setWordlist() with a larger list (e.g. EFF's 7,776-word list) when
     * higher entropy per word matters.
     *
     * @var string[]
     */
    private $wordlist = array(
        'apple', 'anchor', 'arrow', 'autumn', 'bacon', 'badge', 'baker', 'banana',
        'banner', 'barrel', 'basket', 'beach', 'beacon', 'beaver', 'biscuit', 'blanket',
        'blossom', 'blue', 'breeze', 'bridge', 'bright', 'bronze', 'bubble', 'bucket',
        'cabin', 'cactus', 'candle', 'canyon', 'carpet', 'carrot', 'castle', 'cedar',
        'cheese', 'cherry', 'chicken', 'circle', 'citrus', 'cliff', 'cloud', 'clover',
        'cobalt', 'coffee', 'comet', 'copper', 'coral', 'cotton', 'couch', 'crane',
        'cricket', 'crown', 'crystal', 'curtain', 'daisy', 'dance', 'desert', 'diamond',
        'dolphin', 'donkey', 'dragon', 'dream', 'drift', 'drum', 'duck', 'eagle',
        'earth', 'ember', 'engine', 'falcon', 'feather', 'fence', 'fern', 'fig',
        'fire', 'fish', 'flame', 'flute', 'forest', 'forge', 'fox', 'frost',
        'garden', 'garlic', 'gem', 'ghost', 'ginger', 'glacier', 'globe', 'gold',
        'goose', 'grape', 'grass', 'green', 'guitar', 'hammer', 'harbor', 'hawk',
        'hazel', 'heart', 'heron', 'hill', 'honey', 'horse', 'house', 'ice',
        'igloo', 'iron', 'island', 'ivory', 'jade', 'jaguar', 'jazz', 'jelly',
        'jungle', 'keeper', 'key', 'king', 'kite', 'kiwi', 'ladder', 'lake',
        'lamp', 'lantern', 'leaf', 'lemon', 'leopard', 'lion', 'lizard', 'llama',
    );

    /**
     * Replace the built-in wordlist (e.g. with the EFF large list).
     *
     * @param string[] $words Words (lowercase, no spaces).
     * @return $this
     */
    public function setWordlist(array $words)
    {
        $words = array_values(array_filter(array_map('strtolower', $words), function ($w) {
            return '' !== trim($w) && false === strpos($w, ' ');
        }));
        if (count($words) >= 16) {
            $this->wordlist = $words;
        }
        return $this;
    }

    /**
     * Generate a random password.
     *
     * Guarantees at least one character from every enabled set, then shuffles
     * with a Fisher–Yates pass driven by random_int().
     *
     * @param int   $length  Password length (minimum 4).
     * @param array $options lower|upper|digits|symbols booleans; ambiguous
     *                       bool to keep l/I/0/1/O (default: excluded).
     * @return string
     */
    public function generate($length = 16, array $options = array())
    {
        $length = max(4, (int) $length);
        $opts   = array_merge(
            array('lower' => true, 'upper' => true, 'digits' => true, 'symbols' => true, 'ambiguous' => false),
            $options
        );

        $sets = array();
        if ($opts['lower']) {
            $sets[] = self::LOWER . ($opts['ambiguous'] ? 'lio' : '');
        }
        if ($opts['upper']) {
            $sets[] = self::UPPER . ($opts['ambiguous'] ? 'IO' : '');
        }
        if ($opts['digits']) {
            $sets[] = self::DIGITS . ($opts['ambiguous'] ? '01' : '');
        }
        if ($opts['symbols']) {
            $sets[] = self::SYMBOLS;
        }
        if (empty($sets)) {
            $sets[] = self::LOWER;
        }

        // One guaranteed character from each enabled set.
        $chars = array();
        foreach ($sets as $set) {
            $chars[] = $set[random_int(0, strlen($set) - 1)];
        }

        // Fill the rest from the combined pool.
        $pool = implode('', $sets);
        while (count($chars) < $length) {
            $chars[] = $pool[random_int(0, strlen($pool) - 1)];
        }

        // Fisher–Yates shuffle so guaranteed characters are not predictable.
        for ($i = count($chars) - 1; $i > 0; $i--) {
            $j          = random_int(0, $i);
            $tmp        = $chars[$i];
            $chars[$i]  = $chars[$j];
            $chars[$j]  = $tmp;
        }

        return implode('', $chars);
    }

    /**
     * Generate a memorable passphrase of random words.
     *
     * @param int    $words     Number of words (minimum 3).
     * @param string $separator Word separator.
     * @param bool   $addNumber Append a random 2-digit number for extra entropy.
     * @return string
     */
    public function passphrase($words = 4, $separator = '-', $addNumber = false)
    {
        $words  = max(3, (int) $words);
        $count  = count($this->wordlist);
        $picked = array();
        for ($i = 0; $i < $words; $i++) {
            $picked[] = $this->wordlist[random_int(0, $count - 1)];
        }
        $phrase = implode($separator, $picked);
        if ($addNumber) {
            $phrase .= $separator . random_int(10, 99);
        }
        return $phrase;
    }

    /**
     * Generate a numeric PIN.
     *
     * @param int $length PIN length (minimum 4).
     * @return string Zero-padded numeric string.
     */
    public function generatePin($length = 6)
    {
        $length = max(4, (int) $length);
        $pin    = '';
        for ($i = 0; $i < $length; $i++) {
            $pin .= (string) random_int(0, 9);
        }
        return $pin;
    }

    /**
     * Estimate the entropy (in bits) of a generated password of $length
     * characters drawn from the same option set generate() would use.
     *
     * @param int   $length  Password length.
     * @param array $options Same options as generate().
     * @return float
     */
    public function entropyBits($length, array $options = array())
    {
        $opts = array_merge(
            array('lower' => true, 'upper' => true, 'digits' => true, 'symbols' => true, 'ambiguous' => false),
            $options
        );
        $pool = 0;
        if ($opts['lower']) {
            $pool += strlen(self::LOWER) + ($opts['ambiguous'] ? 3 : 0);
        }
        if ($opts['upper']) {
            $pool += strlen(self::UPPER) + ($opts['ambiguous'] ? 2 : 0);
        }
        if ($opts['digits']) {
            $pool += strlen(self::DIGITS) + ($opts['ambiguous'] ? 2 : 0);
        }
        if ($opts['symbols']) {
            $pool += strlen(self::SYMBOLS);
        }
        if (0 === $pool) {
            return 0.0;
        }
        return round(max(4, (int) $length) * (log($pool) / log(2)), 1);
    }

    /**
     * Entropy of a passphrase: words * log2(wordlist size).
     *
     * @param int $words Number of words.
     * @return float
     */
    public function passphraseEntropyBits($words)
    {
        return round(max(3, (int) $words) * (log(count($this->wordlist)) / log(2)), 1);
    }
}
