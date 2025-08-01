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
use Doctrine\ODM\MongoDB\Mapping\ClassMetadata;
use Doctrine\ODM\MongoDB\Query\Builder;
use Doctrine\ODM\MongoDB\Query\Query;
use Doctrine\ODM\MongoDB\Repository\DocumentRepository;
use FOS\OAuthServerBundle\Document\AuthCode;
use FOS\OAuthServerBundle\Document\AuthCodeManager;
use FOS\OAuthServerBundle\Model\AuthCodeInterface;
use MongoDB\Collection;
use MongoDB\Driver\WriteResult;
use MongoDB\DeleteResult;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\MockObject\MockObject;

/**
 * Class AuthCodeManagerTest
 *
 * @author Nikola Petkanski <nikola@petkanski.com>
 */
#[Group('time-sensitive')]
class AuthCodeManagerTest extends \PHPUnit\Framework\TestCase
{
    protected MockObject|DocumentManager $documentManager;
    protected MockObject|DocumentRepository $repository;
    protected string $className;
    protected AuthCodeManager $instance;

    public function setUp(): void
    {
        if (!class_exists(DocumentManager::class)) {
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
        $this->className = 'TestClassName'.\random_bytes(5);

        $this->documentManager
            ->expects($this->once())
            ->method('getRepository')
            ->with($this->className)
            ->willReturn($this->repository)
        ;

        $this->instance = new AuthCodeManager($this->documentManager, $this->className);

        parent::setUp();
    }

    public function testGetClassWillReturnClassName(): void
    {
        $this->assertSame($this->className, $this->instance->getClass());
    }

    public function testFindAuthCodeBy(): void
    {
        $randomResult = new AuthCode();
        $criteria = [
            \random_bytes(10),
        ];

        $this->repository
            ->expects($this->once())
            ->method('findOneBy')
            ->with($criteria)
            ->willReturn($randomResult)
        ;

        $this->assertSame($randomResult, $this->instance->findAuthCodeBy($criteria));
    }

    public function testUpdateAuthCode(): void
    {
        $authCode = $this->getMockBuilder(AuthCodeInterface::class)
            ->disableOriginalConstructor()
            ->getMock()
        ;

        $this->documentManager
            ->expects($this->once())
            ->method('persist')
            ->with($authCode)
        ;

        $this->documentManager
            ->expects($this->once())
            ->method('flush')
            ->with()
        ;

        $this->instance->updateAuthCode($authCode);
    }

    public function testDeleteAuthCode(): void
    {
        $authCode = $this->getMockBuilder(AuthCodeInterface::class)
            ->disableOriginalConstructor()
            ->getMock()
        ;

        $this->documentManager
            ->expects($this->once())
            ->method('remove')
            ->with($authCode)
        ;

        $this->documentManager
            ->expects($this->once())
            ->method('flush')
            ->with()
        ;

        $this->instance->deleteAuthCode($authCode);
    }

    public function testDeleteExpired(): void
    {
        $queryBuilder = $this->getMockBuilder(Builder::class)
            ->disableOriginalConstructor()
            ->getMock()
        ;

        $this->repository
            ->expects($this->once())
            ->method('createQueryBuilder')
            ->with()
            ->willReturn($queryBuilder)
        ;

        $queryBuilder
            ->expects($this->once())
            ->method('remove')
            ->with()
            ->willReturn($queryBuilder)
        ;

        $queryBuilder
            ->expects($this->once())
            ->method('field')
            ->with('expiresAt')
            ->willReturn($queryBuilder)
        ;

        $queryBuilder
            ->expects($this->once())
            ->method('lt')
            ->with(time())
            ->willReturn($queryBuilder)
        ;

        $data = [
            'n' => \random_int( 0, 10),
        ];
        $deleteResult = $this->getMockBuilder(DeleteResult::class)
            ->disableOriginalConstructor()
            ->getMock();
        $deleteResult->expects(self::once())
            ->method('getDeletedCount')
            ->willReturn($data['n']);

        $collection = $this->createMock(Collection::class);
        $collection->expects(self::once())
            ->method('deleteMany')
            ->willReturn($deleteResult)
        ;

        $query = new Query(
            $this->documentManager,
            $this->createMock(ClassMetadata::class),
            $collection,
            [
                'type' => Query::TYPE_REMOVE,
                'query' => [],
            ],
            [],
            false
        );

        $queryBuilder
            ->expects($this->once())
            ->method('getQuery')
            ->with([
                'safe' => true,
            ])
            ->willReturn($query)
        ;

        $this->assertSame($data['n'], $this->instance->deleteExpired());
    }
}
