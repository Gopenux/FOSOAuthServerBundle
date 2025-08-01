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
use FOS\OAuthServerBundle\Document\AccessToken;
use FOS\OAuthServerBundle\Document\TokenManager;
use FOS\OAuthServerBundle\Model\Token;
use MongoDB\Collection;
use MongoDB\DeleteResult;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

/**
 * Class TokenManagerTest
 *
 * @author Nikola Petkanski <nikola@petkanski.com>
 */
#[Group('time-sensitive')]
class TokenManagerTest extends TestCase
{
    protected string $className;
    protected MockObject|DocumentManager $documentManager;
    protected MockObject|DocumentRepository $repository;
    protected TokenManager $instance;

    public function setUp(): void
    {
        if (!class_exists('\Doctrine\ODM\MongoDB\DocumentManager')) {
            $this->markTestSkipped('Doctrine MongoDB ODM has to be installed for this test to run.');
        }

        $this->className = AccessToken::class;
        $this->repository = $this->getMockBuilder(DocumentRepository::class)
            ->disableOriginalConstructor()
            ->getMock()
        ;
        $this->documentManager = $this->getMockBuilder(DocumentManager::class)
            ->disableOriginalConstructor()
            ->getMock()
        ;

        $this->documentManager
            ->expects($this->once())
            ->method('getRepository')
            ->with($this->className)
            ->willReturn($this->repository)
        ;

        $this->instance = new TokenManager($this->documentManager, $this->className);
    }

    public function testFindTokenByToken(): void
    {
        $randomToken = \random_bytes(5);
        $randomResult = new Token();

        $this->repository
            ->expects($this->once())
            ->method('findOneBy')
            ->with([
                'token' => $randomToken,
            ])
            ->willReturn($randomResult)
        ;

        $this->assertSame($randomResult, $this->instance->findTokenByToken($randomToken));
    }

    public function testUpdateTokenPersistsAndFlushes(): void
    {
        $token = $this->getMockBuilder(AccessToken::class)
            ->disableOriginalConstructor()
            ->getMock()
        ;

        $this->documentManager
            ->expects($this->once())
            ->method('persist')
            ->with($token)
        ;

        $this->documentManager
            ->expects($this->once())
            ->method('flush')
            ->with()
        ;

        $this->instance->updateToken($token);
    }

    public function testGetClass(): void
    {
        $this->assertSame($this->className, $this->instance->getClass());
    }

    public function testDeleteToken(): void
    {
        $token = $this->getMockBuilder(AccessToken::class)
            ->disableOriginalConstructor()
            ->getMock()
        ;

        $this->documentManager
            ->expects($this->once())
            ->method('remove')
            ->with($token)
        ;

        $this->documentManager
            ->expects($this->once())
            ->method('flush')
            ->with()
        ;

        $this->instance->deleteToken($token);
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
            'n' => \random_int(0, 5),
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
