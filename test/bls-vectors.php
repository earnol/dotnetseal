<?php
/**
 * bls-vectors.php — checks php/lib/bls12381.php against values produced
 * independently by @noble/curves (in Chrome) and Neo.Cryptography.BLS12_381
 * (in .NET). Both of those agreed byte-for-byte, so these are the reference.
 *
 *   php test/bls-vectors.php
 */

declare(strict_types=1);
require dirname(__DIR__) . '/php/lib/bls12381.php';

$pass = 0;
$fail = 0;

function check(string $name, string $got, string $want): void
{
    global $pass, $fail;
    if ($got === $want) {
        $pass++;
        printf("  ok   %s\n", $name);
    } else {
        $fail++;
        printf("  FAIL %s\n         got  %s\n         want %s\n", $name, $got, $want);
    }
}

// Fixed inputs shared with the JS and .NET runs.
$sHex  = '2a1f9c4e77b30d6154a8e0f3b9c25d8471e6a09fbc3d5e72801964af5c3d2e7b';
$idHex = '0a07851e626b9cf812f6ab3c29ea6ef569a6eb3e5569bf8a99aabbceddeefeff';

$wantX  = '999c7f019362815fbe70fcae3d9647ac0a3c0ad1c71dba305a7b00ca9d6a1517'
        . 'dbf2b7883c43673be0bc436909421e7d12519ea2bed5870d0f4eda21c4e77e2c'
        . '2c2141fad2ee55c2d80e4729a05c367021d371099c840aed460356fbd7b9e28e';
$wantSk = 'adf0d9396e80a48f8fccc4b23c4fd7a2a07556375393d2b084cac9d0e7dcd3ec'
        . '8ac74bb7c29e7bb2208d9ceb51ae0590';

$s  = Bls12381::scalarFromHex($sHex);
$id = Bls12381::scalarFromHex($idHex);

echo "== scalar round trip\n";
check('hex -> scalar -> hex', Bls12381::scalarToHex($s), $sHex);

echo "== master public key  X = s*G2\n";
$t0 = microtime(true);
$X = Bls12381::g2Mul($s);
$g2ms = (microtime(true) - $t0) * 1000;
check('X compressed (96 bytes)', bin2hex(Bls12381::compressG2($X)), $wantX);

echo "== page key  sk = (1/(s+id))*G1\n";
$inv = Bls12381::scalarInv(Bls12381::scalarAdd($s, $id));
$t0 = microtime(true);
$sk = Bls12381::g1Mul($inv);
$g1ms = (microtime(true) - $t0) * 1000;
check('sk compressed (48 bytes)', bin2hex(Bls12381::compressG1($sk)), $wantSk);

echo "== inversion is consistent\n";
check(
    '(s+id) * 1/(s+id) == 1',
    bcmod(bcmul(Bls12381::scalarAdd($s, $id), $inv), Bls12381::R),
    '1'
);

printf("\ntiming: G2 multiply %.0f ms, G1 multiply %.0f ms\n", $g2ms, $g1ms);
printf("%d passed, %d failed\n", $pass, $fail);
exit($fail === 0 ? 0 : 1);
