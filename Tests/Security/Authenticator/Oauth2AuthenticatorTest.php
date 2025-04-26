<?php

namespace FOS\OAuthServerBundle\Tests\Security\Authenticator;

use FOS\OAuthServerBundle\Model\ClientInterface;
use FOS\OAuthServerBundle\Security\Authenticator\Oauth2Authenticator;
use FOS\OAuthServerBundle\Security\Authenticator\Passport\Badge\AccessTokenBadge;
use FOS\OAuthServerBundle\Security\Authenticator\Token\OAuthToken;
use FOS\OAuthServerBundle\Tests\Functional\TestBundle\Entity\AccessToken;
use OAuth2\OAuth2;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\User\UserCheckerInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;

/**
 * Test class for Oauth2Authenticator
 */
class Oauth2AuthenticatorTest extends TestCase
{
    protected Oauth2Authenticator $authenticator;

    protected OAuth2|MockObject $serverService;


    protected UserCheckerInterface|MockObject $user;

    protected AccessToken|MockObject $accessToken;

    protected $userChecker;

    protected function setUp(): void
    {
        $this->serverService = $this->getMockBuilder(OAuth2::class)
            ->disableOriginalConstructor()
            ->getMock();

        $this->userChecker = $this->getMockBuilder(UserCheckerInterface::class)
            ->disableOriginalConstructor()
            ->getMock();

        $this->authenticator = new Oauth2Authenticator($this->serverService, $this->userChecker);

        $this->accessToken = $this->createMock( AccessToken::class );
        $client = $this->createMock( ClientInterface::class );
        $client->method('getUserIdentifier')->willReturn("phpunit");
        $this->accessToken->method('getClient')->willReturn( $client );
    }

    public function testSupportsWithToken(): void
    {
        $request = new Request();

        $this->serverService->method('getBearerToken')->willReturn('token');

        $this->assertTrue($this->authenticator->supports($request));
    }

    public function testSupportsWithoutToken(): void
    {
        $request = new Request();

        $this->serverService->method('getBearerToken')->willReturn(null);

        $this->assertFalse($this->authenticator->supports($request));
    }

    public function testAuthenticateMissingToken(): void
    {
        $request = new Request();

        $this->serverService->method('verifyAccessToken')->willReturn(null);
        $this->expectException(AuthenticationException::class);

        $this->authenticator->authenticate($request);
    }

    public function testAuthenticateClient(): void
    {
        $request = new Request();
        $this->serverService
            ->expects($this->once())
            ->method('getBearerToken')
            ->willReturn('token');

        $this->serverService
            ->expects($this->once())
            ->method('verifyAccessToken')
            ->with('token')
            ->willReturn($this->accessToken)
        ;

        $actual = $this->authenticator->authenticate($request);

        $this->assertInstanceOf(SelfValidatingPassport::class, $actual);
    }

    public function testAuthenticateClientAndUser(): void
    {
        $request = new Request();

        $user = $this->createMock( UserInterface::class );
        $user->method('getUserIdentifier')
            ->willReturn("phpunit");
        $user->method('getRoles')
            ->willReturn(["PHPUNIT_USER"]);
        $this->accessToken->method('getUser')->willReturn( $user );

        $this->serverService
            ->expects($this->once())
            ->method('getBearerToken')
            ->willReturn('token');

        $this->serverService
            ->expects($this->once())
            ->method('verifyAccessToken')
            ->with('token')
            ->willReturn($this->accessToken)
        ;
        $this->accessToken->method('getScope')->willReturn( "PHPUNIT TEST SCOPE" );

        $this->userChecker
            ->expects($this->once())
            ->method('checkPreAuth')
            ->with($user);

        $actual = $this->authenticator->authenticate($request);
        $badge  = $actual->getBadge(AccessTokenBadge::class);

        $this->assertInstanceOf(SelfValidatingPassport::class, $actual);
        $this->assertEquals(["PHPUNIT_USER", "ROLE_PHPUNIT", "ROLE_TEST", "ROLE_SCOPE"], $badge->getRoles());
    }

    public function testCreateTokenWithValidPassport(): void
    {
        $passport = $this->createMock(SelfValidatingPassport::class);
        $accessTokenBadge = $this->createMock(AccessTokenBadge::class);
        $accessToken = $this->createMock(AccessToken::class);

        $user = $this->createMock(UserInterface::class);
        $roles = ['ROLE_USER', 'ROLE_TEST'];
        $token = 'some-token';

        $accessTokenBadge->method('getRoles')->willReturn($roles);
        $accessTokenBadge->method('getAccessToken')->willReturn($accessToken);
        $accessToken->method('getToken')->willReturn($token);
        $accessToken->method('getUser')->willReturn($user);

        $passport->method('getBadge')->with(AccessTokenBadge::class)->willReturn($accessTokenBadge);

        $result = $this->authenticator->createToken($passport, 'test_firewall');
        $this->assertInstanceOf(OAuthToken::class, $result);
        $this->assertSame($token, $result->getToken());
        $this->assertSame($roles, $result->getRoleNames());
        $this->assertSame($user, $result->getUser());
    }

    public function testCreateTokenWithoutUser(): void
    {
        $passport = $this->createMock(SelfValidatingPassport::class);
        $accessTokenBadge = $this->createMock(AccessTokenBadge::class);
        $accessToken = $this->createMock(AccessToken::class);

        $roles = ['ROLE_USER'];
        $token = 'some-token';

        $accessTokenBadge->method('getRoles')->willReturn($roles);
        $accessTokenBadge->method('getAccessToken')->willReturn($accessToken);
        $accessToken->method('getToken')->willReturn($token);
        $accessToken->method('getUser')->willReturn(null);

        $passport->method('getBadge')->with(AccessTokenBadge::class)->willReturn($accessTokenBadge);

        $result = $this->authenticator->createToken($passport, 'test_firewall');
        $this->assertInstanceOf(OAuthToken::class, $result);
        $this->assertSame($token, $result->getToken());
        $this->assertSame($roles, $result->getRoleNames());
        $this->assertNull($result->getUser());
    }

    public function testOnAuthenticationSuccess()
    {
        $this->assertNull($this->authenticator->onAuthenticationSuccess(new Request(), new OAuthToken(), "main"));
    }

    public function testOnAuthenticationFailure()
    {
        $exception = new AuthenticationException("phpunit");
        $expected = new JsonResponse([
            'message' => "An authentication exception occurred.",
        ], 401);

        $this->assertEquals($expected, $this->authenticator->onAuthenticationFailure(new Request(), $exception));
    }
}