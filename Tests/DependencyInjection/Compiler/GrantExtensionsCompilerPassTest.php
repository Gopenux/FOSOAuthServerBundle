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

namespace FOS\OAuthServerBundle\Tests\DependencyInjection\Compiler;

use FOS\OAuthServerBundle\DependencyInjection\Compiler\GrantExtensionsCompilerPass;
use FOS\OAuthServerBundle\Storage\GrantExtensionDispatcherInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Exception\InvalidArgumentException;
use Symfony\Component\DependencyInjection\ParameterBag\ParameterBag;
use Symfony\Component\DependencyInjection\Reference;

/**
 * Class GrantExtensionsCompilerPassTest.
 *
 * @author Nikola Petkanski <nikola@petkanski.com>
 */
class GrantExtensionsCompilerPassTest extends \PHPUnit\Framework\TestCase
{
    /**
     * @var GrantExtensionsCompilerPass
     */
    protected $instance;

    public function setUp(): void
    {
        $this->instance = new GrantExtensionsCompilerPass();

        parent::setUp();
    }

    public function testProcessWillNotDoAnythingIfTheStorageDoesNotImplementOurInterface(): void
    {
        $container = $this->getMockBuilder(ContainerBuilder::class)
            ->disableOriginalConstructor()
            ->onlyMethods([
                'findDefinition',
                'getParameterBag',
            ])
            ->getMock()
        ;
        $storageDefinition = $this->getMockBuilder(Definition::class)
            ->disableOriginalConstructor()
            ->getMock()
        ;
        $parameterBag = $this->getMockBuilder(ParameterBag::class)
            ->disableOriginalConstructor()
            ->getMock()
        ;

        $className = 'stdClassUnresolved'.random_bytes(5);
        $resolvedClassName = 'stdClass';

        $container
            ->expects($this->once())
            ->method('findDefinition')
            ->with('fos_oauth_server.storage')
            ->willReturn($storageDefinition)
        ;

        $storageDefinition
            ->expects($this->once())
            ->method('getClass')
            ->with()
            ->willReturn($className)
        ;

        $container
            ->expects($this->once())
            ->method('getParameterBag')
            ->with()
            ->willReturn($parameterBag)
        ;

        $parameterBag
            ->expects($this->once())
            ->method('resolveValue')
            ->with($className)
            ->willReturn($resolvedClassName)
        ;

        $this->instance->process($container);
    }

    public function testProcessWillFailIfUriIsEmpty(): void
    {
        $container = $this->createPartialMock(ContainerBuilder::class, [
                'findDefinition',
                'getParameterBag',
                'findTaggedServiceIds',
        ])
        ;
        $storageDefinition = $this->getMockBuilder(Definition::class)
            ->disableOriginalConstructor()
            ->getMock()
        ;
        $parameterBag = $this->getMockBuilder(ParameterBag::class)
            ->disableOriginalConstructor()
            ->getMock()
        ;

        $storageInstance = $this->getMockBuilder(GrantExtensionDispatcherInterface::class)
            ->disableOriginalConstructor()
            ->getMock()
        ;

        $className = 'stdClassUnresolved'.random_bytes(5);
        $resolvedClassName = get_class($storageInstance);

        $container
            ->expects($this->once())
            ->method('findDefinition')
            ->with('fos_oauth_server.storage')
            ->willReturn($storageDefinition)
        ;

        $storageDefinition
            ->expects($this->once())
            ->method('getClass')
            ->with()
            ->willReturn($className)
        ;

        $container
            ->expects($this->once())
            ->method('getParameterBag')
            ->with()
            ->willReturn($parameterBag)
        ;

        $parameterBag
            ->expects($this->once())
            ->method('resolveValue')
            ->with($className)
            ->willReturn($resolvedClassName)
        ;

        $data = [
            'service.id.1' => [
                [
                    'uri' => 'uri11',
                ],
                [
                    'uri' => '',
                ],
            ],
        ];

        $container
            ->expects($this->once())
            ->method('findTaggedServiceIds')
            ->with('fos_oauth_server.grant_extension')
            ->willReturn($data)
        ;

        $exceptionMessage = 'Service "%s" must define the "uri" attribute on "fos_oauth_server.grant_extension" tags.';

        $invocations = [];
        foreach ($data as $id => $tags) {
            foreach ($tags as $tag) {
                if (empty($tag['uri'])) {
                    $exceptionMessage = sprintf($exceptionMessage, $id);
                    break;
                }
                $invocations[] = [
                    'setGrantExtension',
                    [
                        $tag['uri'],
                        new Reference($id),
                    ],
                    false
                ];
            }
        }

        $storageDefinition
            ->expects($matcher = $this->exactly(count($invocations)))
            ->method('addMethodCall')
            ->with($this->callback(function (...$args) use ($invocations, $matcher) {
                $this->assertEquals($args, $invocations[$matcher->numberOfInvocations()-1]);
                return true;
            }))
        ;

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage($exceptionMessage);

        $this->instance->process($container);
    }

    public function testProcess(): void
    {
        $container = $this->getMockBuilder(ContainerBuilder::class)
            ->disableOriginalConstructor()
            ->onlyMethods([
                'findDefinition',
                'getParameterBag',
                'findTaggedServiceIds',
            ])
            ->getMock()
        ;
        $storageDefinition = $this->getMockBuilder(Definition::class)
            ->disableOriginalConstructor()
            ->getMock()
        ;
        $parameterBag = $this->getMockBuilder(ParameterBag::class)
            ->disableOriginalConstructor()
            ->getMock()
        ;

        $storageInstance = $this->getMockBuilder(GrantExtensionDispatcherInterface::class)
            ->disableOriginalConstructor()
            ->getMock()
        ;

        $className = 'stdClassUnresolved'.random_bytes(5);
        $resolvedClassName = get_class($storageInstance);

        $container
            ->expects($this->once())
            ->method('findDefinition')
            ->with('fos_oauth_server.storage')
            ->willReturn($storageDefinition)
        ;

        $storageDefinition
            ->expects($this->once())
            ->method('getClass')
            ->with()
            ->willReturn($className)
        ;

        $container
            ->expects($this->once())
            ->method('getParameterBag')
            ->with()
            ->willReturn($parameterBag)
        ;

        $parameterBag
            ->expects($this->once())
            ->method('resolveValue')
            ->with($className)
            ->willReturn($resolvedClassName)
        ;

        $data = [
            'service.id.1' => [
                [
                    'uri' => 'uri11',
                ],
                [
                    'uri' => 'uri12',
                ],
            ],
            'service.id.2' => [
                [
                    'uri' => 'uri21',
                ],
                [
                    'uri' => 'uri22',
                ],
            ],
        ];

        $container
            ->expects($this->once())
            ->method('findTaggedServiceIds')
            ->with('fos_oauth_server.grant_extension')
            ->willReturn($data)
        ;

        $invocations = [];
        foreach ($data as $id => $tags) {
            foreach ($tags as $tag) {
                $invocations[] = [
                    'setGrantExtension',
                    [
                        $tag['uri'],
                        new Reference($id),
                    ],
                    false
                ];
            }
        }
        $storageDefinition
                ->expects($matcher = $this->exactly(count($invocations)))
                ->method('addMethodCall')
                ->with($this->callback(function (...$args) use ($invocations, $matcher) {
                    $this->assertEquals($args, $invocations[$matcher->numberOfInvocations()-1]);
                    return true;
                }))
        ;

        $this->instance->process($container);
    }
}
