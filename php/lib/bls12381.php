<?php
/**
 * bls12381.php — the minimum of BLS12-381 needed by the key issuer, in pure PHP
 * on bcmath.
 *
 * This exists because every PHP elliptic-curve library requires ext-gmp, which
 * the available PHP builds do not have. It stays on the issuing server and is
 * never distributed, so its only job is to be correct and to agree byte-for-byte
 * with @noble/curves in the browser and Neo.Cryptography.BLS12_381 in .NET.
 * test/bls-vectors.php checks exactly that.
 *
 * Scope, deliberately small:
 *   - Fp and Fp2 arithmetic
 *   - scalar multiplication of the G1 and G2 generators (Jacobian, a = 0)
 *   - the standard 48/96-byte compressed point encodings
 *   - scalar arithmetic modulo the group order
 *
 * No pairing, no hash-to-curve, no general point arithmetic: the issuer never
 * needs them.
 */

declare(strict_types=1);

bcscale(0);

final class Bls12381
{
    /** Base field modulus. */
    public const P = '4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559787';

    /** Order of the prime-order subgroups. */
    public const R = '52435875175126190479447740508185965837690552500527637822603658699938581184513';

    /** G1 generator, affine. */
    private const G1_X = '3685416753713387016781088315183077757961620795782546409894578378688607592378376318836054947676345821548104185464507';
    private const G1_Y = '1339506544944476473020471379941921221584933875938349620426543736416511423956333506472724655353366534992391756441569';

    /** G2 generator, affine; each coordinate is c0 + c1*u. */
    private const G2_X0 = '352701069587466618187139116011060144890029952792775240219908644239793785735715026873347600343865175952761926303160';
    private const G2_X1 = '3059144344244213709971259814753781636986470325476647558659373206291635324768958432433509563104347017837885763365758';
    private const G2_Y0 = '1985150602287291935568054521177171638300868978215655730859378665066344726373823718423869104263333984641494340347905';
    private const G2_Y1 = '927553665492332455747201965776037880757740193453592970025027978793976877002675564980949289727957565575433344219582';

    // ---------------------------------------------------------------- scalars

    public static function scalarAdd(string $a, string $b): string
    {
        return bcmod(bcadd($a, $b), self::R);
    }

    /** Fermat inversion; R is prime, so a^(R-2) is a^-1. */
    public static function scalarInv(string $a): string
    {
        $a = bcmod($a, self::R);
        if ($a === '0') {
            throw new RuntimeException('scalar is not invertible');
        }
        return bcpowmod($a, bcsub(self::R, '2'), self::R);
    }

    /** Reduce raw bytes (big-endian) to a scalar. Used to turn a page id into an identity. */
    public static function scalarFromBytes(string $bytes): string
    {
        $n = '0';
        foreach (str_split($bytes) as $byte) {
            $n = bcadd(bcmul($n, '256'), (string) ord($byte));
        }
        return bcmod($n, self::R);
    }

    public static function scalarToHex(string $dec): string
    {
        return str_pad(self::decToHex($dec), 64, '0', STR_PAD_LEFT);
    }

    public static function scalarFromHex(string $hex): string
    {
        return bcmod(self::hexToDec($hex), self::R);
    }

    // ------------------------------------------------------- generator multiples

    /** @return array{0:string,1:string} affine (x, y) in Fp */
    public static function g1Mul(string $scalar): array
    {
        $fp = new Fp();
        $point = self::jacobianMul(
            $fp,
            [self::G1_X, self::G1_Y, '1'],
            $scalar
        );
        return self::jacobianToAffine($fp, $point);
    }

    /** @return array{0:array{0:string,1:string},1:array{0:string,1:string}} affine (x, y) in Fp2 */
    public static function g2Mul(string $scalar): array
    {
        $fp2 = new Fp2();
        $point = self::jacobianMul(
            $fp2,
            [[self::G2_X0, self::G2_X1], [self::G2_Y0, self::G2_Y1], $fp2->one()],
            $scalar
        );
        return self::jacobianToAffine($fp2, $point);
    }

    // ------------------------------------------------------------- encodings

    /**
     * 48 bytes: big-endian x, with the compression flag in bit 7 and the y-sign
     * in bit 5 of the first byte. x < 2^381 always leaves those bits free.
     */
    public static function compressG1(array $affine): string
    {
        [$x, $y] = $affine;
        $out = self::fpToBytes($x);
        $flags = 0x80 | (self::isLexLargestFp($y) ? 0x20 : 0x00);
        $out[0] = chr(ord($out[0]) | $flags);
        return $out;
    }

    /** 96 bytes: x.c1 then x.c0, same flag layout in the first byte. */
    public static function compressG2(array $affine): string
    {
        [$x, $y] = $affine;
        $out = self::fpToBytes($x[1]) . self::fpToBytes($x[0]);
        $flags = 0x80 | (self::isLexLargestFp2($y) ? 0x20 : 0x00);
        $out[0] = chr(ord($out[0]) | $flags);
        return $out;
    }

    private static function isLexLargestFp(string $v): bool
    {
        // v > (P-1)/2
        return bccomp($v, bcdiv(bcsub(self::P, '1'), '2')) > 0;
    }

    private static function isLexLargestFp2(array $v): bool
    {
        if ($v[1] !== '0') {
            return self::isLexLargestFp($v[1]);
        }
        return self::isLexLargestFp($v[0]);
    }

    private static function fpToBytes(string $v): string
    {
        $out = str_repeat("\0", 48);
        for ($i = 47; $i >= 0; $i--) {
            $out[$i] = chr((int) bcmod($v, '256'));
            $v = bcdiv($v, '256');
        }
        return $out;
    }

    // -------------------------------------------------------- curve arithmetic

    /**
     * Left-to-right double-and-add over Jacobian coordinates. The curve has
     * a = 0, so neither formula needs the b coefficient.
     *
     * @param Fp|Fp2 $f
     */
    private static function jacobianMul($f, array $base, string $scalar): array
    {
        $acc = [$f->zero(), $f->one(), $f->zero()];   // point at infinity
        foreach (self::bits($scalar) as $bit) {
            $acc = self::jacobianDouble($f, $acc);
            if ($bit === 1) {
                $acc = self::jacobianAdd($f, $acc, $base);
            }
        }
        return $acc;
    }

    /** @return int[] most significant bit first */
    private static function bits(string $scalar): array
    {
        $bits = [];
        $n = bcmod($scalar, self::R);
        while (bccomp($n, '0') > 0) {
            $bits[] = (int) bcmod($n, '2');
            $n = bcdiv($n, '2');
        }
        return array_reverse($bits);
    }

    /** dbl-2009-l */
    private static function jacobianDouble($f, array $p): array
    {
        [$x, $y, $z] = $p;
        if ($f->isZero($z)) {
            return $p;
        }
        $a = $f->sqr($x);
        $b = $f->sqr($y);
        $c = $f->sqr($b);
        $d = $f->mulInt($f->sub($f->sub($f->sqr($f->add($x, $b)), $a), $c), 2);
        $e = $f->mulInt($a, 3);
        $ff = $f->sqr($e);
        $x3 = $f->sub($ff, $f->mulInt($d, 2));
        $y3 = $f->sub($f->mul($e, $f->sub($d, $x3)), $f->mulInt($c, 8));
        $z3 = $f->mulInt($f->mul($y, $z), 2);
        return [$x3, $y3, $z3];
    }

    /** add-2007-bl */
    private static function jacobianAdd($f, array $p, array $q): array
    {
        [$x1, $y1, $z1] = $p;
        [$x2, $y2, $z2] = $q;
        if ($f->isZero($z1)) {
            return $q;
        }
        if ($f->isZero($z2)) {
            return $p;
        }
        $z1z1 = $f->sqr($z1);
        $z2z2 = $f->sqr($z2);
        $u1 = $f->mul($x1, $z2z2);
        $u2 = $f->mul($x2, $z1z1);
        $s1 = $f->mul($f->mul($y1, $z2), $z2z2);
        $s2 = $f->mul($f->mul($y2, $z1), $z1z1);
        $h = $f->sub($u2, $u1);
        $rr = $f->mulInt($f->sub($s2, $s1), 2);

        if ($f->isZero($h)) {
            if ($f->isZero($rr)) {
                return self::jacobianDouble($f, $p);
            }
            return [$f->zero(), $f->one(), $f->zero()];   // opposite points
        }

        $i = $f->sqr($f->mulInt($h, 2));
        $j = $f->mul($h, $i);
        $v = $f->mul($u1, $i);
        $x3 = $f->sub($f->sub($f->sqr($rr), $j), $f->mulInt($v, 2));
        $y3 = $f->sub($f->mul($rr, $f->sub($v, $x3)), $f->mulInt($f->mul($s1, $j), 2));
        $z3 = $f->mul(
            $f->sub($f->sub($f->sqr($f->add($z1, $z2)), $z1z1), $z2z2),
            $h
        );
        return [$x3, $y3, $z3];
    }

    private static function jacobianToAffine($f, array $p): array
    {
        [$x, $y, $z] = $p;
        if ($f->isZero($z)) {
            throw new RuntimeException('point at infinity has no affine form');
        }
        $zInv = $f->inv($z);
        $zInv2 = $f->sqr($zInv);
        $zInv3 = $f->mul($zInv2, $zInv);
        return [$f->mul($x, $zInv2), $f->mul($y, $zInv3)];
    }

    // ------------------------------------------------------------- hex helpers

    private static function decToHex(string $dec): string
    {
        $hex = '';
        while (bccomp($dec, '0') > 0) {
            $hex = dechex((int) bcmod($dec, '16')) . $hex;
            $dec = bcdiv($dec, '16');
        }
        return $hex === '' ? '0' : $hex;
    }

    private static function hexToDec(string $hex): string
    {
        $dec = '0';
        foreach (str_split(strtolower(ltrim($hex, '0x'))) as $c) {
            $dec = bcadd(bcmul($dec, '16'), (string) hexdec($c));
        }
        return $dec;
    }
}

/** Fp: elements are decimal strings. */
final class Fp
{
    public function zero(): string { return '0'; }
    public function one(): string { return '1'; }
    public function isZero($a): bool { return $a === '0'; }
    public function add($a, $b) { return bcmod(bcadd($a, $b), Bls12381::P); }
    public function sub($a, $b) { return bcmod(bcadd(bcsub($a, $b), Bls12381::P), Bls12381::P); }
    public function mul($a, $b) { return bcmod(bcmul($a, $b), Bls12381::P); }
    public function sqr($a) { return bcmod(bcmul($a, $a), Bls12381::P); }
    public function mulInt($a, int $n) { return bcmod(bcmul($a, (string) $n), Bls12381::P); }
    public function inv($a) { return bcpowmod($a, bcsub(Bls12381::P, '2'), Bls12381::P); }
}

/** Fp2 = Fp[u]/(u^2 + 1): elements are [c0, c1]. */
final class Fp2
{
    private Fp $fp;

    public function __construct()
    {
        $this->fp = new Fp();
    }

    public function zero(): array { return ['0', '0']; }
    public function one(): array { return ['1', '0']; }
    public function isZero($a): bool { return $a[0] === '0' && $a[1] === '0'; }

    public function add($a, $b): array
    {
        return [$this->fp->add($a[0], $b[0]), $this->fp->add($a[1], $b[1])];
    }

    public function sub($a, $b): array
    {
        return [$this->fp->sub($a[0], $b[0]), $this->fp->sub($a[1], $b[1])];
    }

    /** (a0 + a1 u)(b0 + b1 u) = (a0b0 - a1b1) + (a0b1 + a1b0) u */
    public function mul($a, $b): array
    {
        $f = $this->fp;
        return [
            $f->sub($f->mul($a[0], $b[0]), $f->mul($a[1], $b[1])),
            $f->add($f->mul($a[0], $b[1]), $f->mul($a[1], $b[0])),
        ];
    }

    /** (a0 + a1)(a0 - a1) + 2 a0 a1 u */
    public function sqr($a): array
    {
        $f = $this->fp;
        return [
            $f->mul($f->add($a[0], $a[1]), $f->sub($a[0], $a[1])),
            $f->mulInt($f->mul($a[0], $a[1]), 2),
        ];
    }

    public function mulInt($a, int $n): array
    {
        return [$this->fp->mulInt($a[0], $n), $this->fp->mulInt($a[1], $n)];
    }

    /** conjugate divided by the norm */
    public function inv($a): array
    {
        $f = $this->fp;
        $norm = $f->add($f->sqr($a[0]), $f->sqr($a[1]));
        $t = $f->inv($norm);
        return [$f->mul($a[0], $t), $f->sub('0', $f->mul($a[1], $t))];
    }
}
