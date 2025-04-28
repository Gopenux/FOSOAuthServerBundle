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

namespace FOS\OAuthServerBundle\Tests;

use FOS\OAuthServerBundle\DependencyInjection\Compiler;
use FOS\OAuthServerBundle\DependencyInjection\Security\Factory\OAuthFactory;
use FOS\OAuthServerBundle\FOSOAuthServerBundle;
use PHPUnit\Framework\MockObject\MockObject;
use Symfony\Bundle\SecurityBundle\DependencyInjection\SecurityExtension;
use Symfony\Component\DependencyInjection\ContainerBuilder;

class FOSOAuthServerBundleTest extends \PHPUnit\Framework\TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
    }

    public function testConstruction(): void
    {
        $bundle = new FOSOAuthServerBundle();

        /** @var ContainerBuilder|MockObject $containerBuilder */
        $containerBuilder = $this->getMockBuilder(ContainerBuilder::class)
            ->disableOriginalConstructor()
            ->onlyMethods([
                'getExtension',
                'addCompilerPass',
            ])
            ->getMock()
        ;

        /** @var SecurityExtension|MockObject $securityExtension */
        $securityExtension = $this->getMockBuilder(SecurityExtension::class)
            ->disableOriginalConstructor()
            ->getMock()
        ;

        $containerBuilder
            ->expects($this->any())
            ->method('getExtension')
            ->with('security')
            ->willReturn($securityExtension)
        ;

        $securityExtension
            ->expects($this->any())
            ->method('addAuthenticatorFactory')
            ->with(new OAuthFactory())
        ;

        $invocations = [
            new Compiler\GrantExtensionsCompilerPass(),
            new Compiler\RequestStackCompilerPass()
        ];
        $matcher = $this->exactly(count($invocations));
        $containerBuilder
            ->expects($matcher)
            ->method('addCompilerPass')
            ->with($this->callback(function ($param) use (&$invocations, $matcher) {
                $this->assertEquals( $param, $invocations[$matcher->numberOfInvocations()-1]);
                return true;
            }))
            ->willReturnOnConsecutiveCalls(
                $containerBuilder,
                $containerBuilder
            )
        ;

        $bundle->build($containerBuilder);
    }
}
