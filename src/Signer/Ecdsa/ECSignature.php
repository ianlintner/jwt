<?php
declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2018 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */
namespace Lcobucci\JWT\Signer\Ecdsa;

use InvalidArgumentException;
use RuntimeException;
use const STR_PAD_LEFT;
use function dechex;
use function hexdec;
use function mb_strlen;
use function mb_substr;
use function pack;
use function str_pad;
use function unpack;

final class ECSignature implements PointsManipulator
{
    public function toEcPoint(string $signature, int $partLength): string
    {
        $signature = unpack('H*', $signature)[1];
        if (mb_strlen($signature, '8bit') !== 2 * $partLength) {
            throw new InvalidArgumentException('Invalid length.');
        }
        $R = mb_substr($signature, 0, $partLength, '8bit');
        $S = mb_substr($signature, $partLength, null, '8bit');

        $R  = self::preparePositiveInteger($R);
        $Rl = (int) (mb_strlen($R, '8bit') / 2);
        $S  = self::preparePositiveInteger($S);
        $Sl = (int) (mb_strlen($S, '8bit') / 2);

        return pack(
            'H*',
            '30' . ($Rl + $Sl + 4 > 128 ? '81' : '') . dechex($Rl + $Sl + 4)
            . '02' . dechex($Rl) . $R
            . '02' . dechex($Sl) . $S
        );
    }

    public function fromEcPoint(string $signature, int $partLength): string
    {
        $hex = unpack('H*', $signature)[1];
        if (mb_substr($hex, 0, 2, '8bit') !== '30') { // SEQUENCE
            throw new RuntimeException();
        }
        if (mb_substr($hex, 2, 2, '8bit') === '81') { // LENGTH > 128
            $hex = mb_substr($hex, 6, null, '8bit');
        } else {
            $hex = mb_substr($hex, 4, null, '8bit');
        }
        if (mb_substr($hex, 0, 2, '8bit') !== '02') { // INTEGER
            throw new RuntimeException();
        }

        $Rl = (int) hexdec(mb_substr($hex, 2, 2, '8bit'));
        $R  = self::retrievePositiveInteger(mb_substr($hex, 4, $Rl * 2, '8bit'));
        $R  = str_pad($R, $partLength, '0', STR_PAD_LEFT);

        $hex = mb_substr($hex, 4 + $Rl * 2, null, '8bit');
        if (mb_substr($hex, 0, 2, '8bit') !== '02') { // INTEGER
            throw new RuntimeException();
        }
        $Sl = (int) hexdec(mb_substr($hex, 2, 2, '8bit'));
        $S  = self::retrievePositiveInteger(mb_substr($hex, 4, $Sl * 2, '8bit'));
        $S  = str_pad($S, $partLength, '0', STR_PAD_LEFT);

        return pack('H*', $R . $S);
    }

    private static function preparePositiveInteger(string $data): string
    {
        if (mb_substr($data, 0, 2, '8bit') > '7f') {
            return '00' . $data;
        }
        while (mb_substr($data, 0, 2, '8bit') === '00' && mb_substr($data, 2, 2, '8bit') <= '7f') {
            $data = mb_substr($data, 2, null, '8bit');
        }

        return $data;
    }

    private static function retrievePositiveInteger(string $data): string
    {
        while (mb_substr($data, 0, 2, '8bit') === '00' && mb_substr($data, 2, 2, '8bit') > '7f') {
            $data = mb_substr($data, 2, null, '8bit');
        }

        return $data;
    }
}
