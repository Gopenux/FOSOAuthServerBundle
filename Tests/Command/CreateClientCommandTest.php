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

namespace FOS\OAuthServerBundle\Tests\Command;

use FOS\OAuthServerBundle\Command\CreateClientCommand;
use FOS\OAuthServerBundle\Model\ClientManagerInterface;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Console\Application;
use Symfony\Component\Console\Tester\CommandTester;

class CreateClientCommandTest extends TestCase
{
    /**
     * @var CreateClientCommand
     */
    private $command;

    /**
     * @var MockObject|ClientManagerInterface
     */
    private $clientManager;

    /**
     * {@inheritdoc}
     */
    protected function setUp(): void
    {
        $this->clientManager = $this->getMockBuilder(ClientManagerInterface::class)->disableOriginalConstructor()->getMock();
        $command = new CreateClientCommand($this->clientManager);

        $application = new Application();
        $application->add($command);

        /** @var CreateClientCommand $command */
        $command = $application->find($command->getName());

        $this->command = $command;
    }

    #[DataProvider('clientProvider')]
    public function testItShouldCreateClient($client): void
    {
        $this
            ->clientManager
            ->expects($this->any())
            ->method('createClient')
            ->willReturn(new $client())
        ;

        $commandTester = new CommandTester($this->command);

        $commandTester->execute([
            'command' => $this->command->getName(),
            '--redirect-uri' => ['https://www.example.com/oauth2/callback'],
            '--grant-type' => [
                'authorization_code',
                'password',
                'refresh_token',
                'token',
                'client_credentials',
            ],
        ]);

        $this->assertSame(0, $commandTester->getStatusCode());

        $output = $commandTester->getDisplay();

        $this->assertStringContainsString('Client ID', $output);
        $this->assertStringContainsString('Client Secret', $output);
    }

    /**
     * @return array
     */
    public static function clientProvider()
    {
        return [
            ['FOS\OAuthServerBundle\Document\Client'],
            ['FOS\OAuthServerBundle\Entity\Client'],
            ['FOS\OAuthServerBundle\Model\Client'],
        ];
    }
}
