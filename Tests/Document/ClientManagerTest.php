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

namespace FOS\OAuthServerBundle\Tests\Document;

use Doctrine\ODM\MongoDB\DocumentManager;
use Doctrine\ODM\MongoDB\Repository\DocumentRepository;
use FOS\OAuthServerBundle\Document\Client;
use FOS\OAuthServerBundle\Document\ClientManager;
use FOS\OAuthServerBundle\Model\ClientInterface;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

/**
 * Class ClientManagerTest.
 *
 * @author Nikola Petkanski <nikola@petkanski.com>
 */
class ClientManagerTest extends TestCase
{
    protected MockObject|DocumentManager $documentManager;
    protected string $className;
    protected MockObject|DocumentRepository $repository;
    protected ClientManager $instance;

    public function setUp(): void
    {
        if (!class_exists('\Doctrine\ODM\MongoDB\DocumentManager')) {
            $this->markTestSkipped('Doctrine MongoDB ODM has to be installed for this test to run.');
        }

        $this->documentManager = $this->getMockBuilder(DocumentManager::class)
            ->disableOriginalConstructor()
            ->getMock()
        ;
        $this->repository = $this->getMockBuilder(DocumentRepository::class)
            ->disableOriginalConstructor()
            ->getMock()
        ;
        $this->className = 'RandomClassName'.\random_bytes(5);

        $this->documentManager
            ->expects($this->once())
            ->method('getRepository')
            ->with($this->className)
            ->willReturn($this->repository)
        ;

        $this->instance = new ClientManager($this->documentManager, $this->className);

        parent::setUp();
    }

    public function testGetClass(): void
    {
        $this->assertSame($this->className, $this->instance->getClass());
    }

    public function testFindClientBy(): void
    {
        $randomResult = new Client();
        $criteria = [
            \random_bytes(5),
        ];

        $this->repository
            ->expects($this->once())
            ->method('findOneBy')
            ->with($criteria)
            ->willReturn($randomResult)
        ;

        $this->assertSame($randomResult, $this->instance->findClientBy($criteria));
    }

    public function testUpdateClient(): void
    {
        $client = $this->getMockBuilder(ClientInterface::class)
            ->disableOriginalConstructor()
            ->getMock()
        ;

        $this->documentManager
            ->expects($this->once())
            ->method('persist')
            ->with($client)
        ;

        $this->documentManager
            ->expects($this->once())
            ->method('flush')
            ->with()
        ;

        $this->instance->updateClient($client);
    }

    public function testDeleteClient(): void
    {
        $client = $this->getMockBuilder(ClientInterface::class)
            ->disableOriginalConstructor()
            ->getMock()
        ;

        $this->documentManager
            ->expects($this->once())
            ->method('remove')
            ->with($client)
        ;

        $this->documentManager
            ->expects($this->once())
            ->method('flush')
            ->with()
        ;

        $this->instance->deleteClient($client);
    }
}
