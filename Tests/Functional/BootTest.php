<?php

declare(strict_types=1);

/*
 * This file is part of the FOSOAuthServerBundle package.
 *
 * (c) FriendsOfSymfony <http://friendsofsymfony.github.com/>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FOS\OAuthServerBundle\Tests\Functional;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\RunInSeparateProcess;

class BootTest extends TestCase
{

    #[DataProvider('getTestBootData')]
    #[RunInSeparateProcess]
    public function testBoot($env): void
    {
        try {
            $kernel = static::createKernel(['env' => $env]);
            $kernel->boot();

            // no exceptions were thrown
            self::assertTrue(true);
        } catch (\Exception $exception) {
            $this->fail($exception->getMessage());
        }
    }

    public static function getTestBootData(): array
    {
        return [
            ['orm'],
        ];
    }
}
