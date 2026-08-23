<?php

namespace Atwx\SilverGateApi\Tests;

use Atwx\SilverGateApi\Manager\OAuth\OAuthClient;
use Atwx\SilverGateApi\Manager\OAuth\OAuthCode;
use Atwx\SilverGateApi\Manager\OAuth\OAuthToken;
use SilverStripe\Core\Config\Config;
use SilverStripe\Dev\SapphireTest;
use SilverStripe\ORM\FieldType\DBDatetime;
use SilverStripe\Security\Member;

/**
 * The parts of the OAuth flow that decide whether a stolen code or token is
 * usable.
 */
class OAuthTest extends SapphireTest
{
    protected static $fixture_file = 'OAuthTest.yml';

    private function client(array $uris = ['http://localhost:1234/cb']): OAuthClient
    {
        return OAuthClient::register('Test client', $uris);
    }

    private function member(): Member
    {
        return $this->objFromFixture(Member::class, 'operator');
    }

    private function challengeFor(string $verifier): string
    {
        return rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');
    }

    public function testRedirectUriMustMatchExactly(): void
    {
        $client = $this->client(['https://example.com/callback']);

        $this->assertTrue($client->allowsRedirectUri('https://example.com/callback'));
        $this->assertFalse($client->allowsRedirectUri('https://example.com/callback/sub'));
        $this->assertFalse($client->allowsRedirectUri('https://example.com/callback?x=1'));
        $this->assertFalse($client->allowsRedirectUri('https://evil.example/callback'));
    }

    public function testClientIdentifiersAreUnique(): void
    {
        $this->assertNotSame(
            $this->client()->ClientIdentifier,
            $this->client()->ClientIdentifier
        );
    }

    public function testCodeIsNotStoredInPlainText(): void
    {
        $plain = OAuthCode::issue($this->client(), $this->member(), 'challenge', 'http://localhost:1234/cb', 'mcp');
        $code = OAuthCode::findByPlainCode($plain);

        $this->assertNotNull($code);
        $this->assertNotSame($plain, $code->CodeHash);
        $this->assertSame(hash('sha256', $plain), $code->CodeHash);
    }

    public function testCodeMatchesOnlyItsOwnVerifier(): void
    {
        $verifier = 'a-verifier-of-reasonable-length-000000000000';
        $plain = OAuthCode::issue(
            $this->client(),
            $this->member(),
            $this->challengeFor($verifier),
            'http://localhost:1234/cb',
            'mcp'
        );

        $code = OAuthCode::findByPlainCode($plain);

        $this->assertTrue($code->matchesVerifier($verifier));
        $this->assertFalse($code->matchesVerifier('some-other-verifier'));
    }

    public function testCodeIsSingleUse(): void
    {
        $plain = OAuthCode::issue($this->client(), $this->member(), 'c', 'http://localhost:1234/cb', 'mcp');
        $code = OAuthCode::findByPlainCode($plain);

        $this->assertTrue($code->isUsable());
        $code->consume();
        $this->assertFalse($code->isUsable());
    }

    public function testCodeExpires(): void
    {
        Config::modify()->set(OAuthCode::class, 'lifetime', 60);
        $plain = OAuthCode::issue($this->client(), $this->member(), 'c', 'http://localhost:1234/cb', 'mcp');

        DBDatetime::set_mock_now(date('Y-m-d H:i:s', time() + 120));
        $this->assertFalse(OAuthCode::findByPlainCode($plain)->isUsable());
        DBDatetime::clear_mock_now();
    }

    public function testAccessTokenIsNotStoredInPlainText(): void
    {
        $issued = OAuthToken::issue($this->client(), $this->member(), 'mcp');

        $this->assertNotSame($issued['access'], $issued['token']->AccessTokenHash);
        $this->assertNotNull(OAuthToken::findByAccessToken($issued['access']));
    }

    public function testRefreshTokenIsSeparateFromAccessToken(): void
    {
        $issued = OAuthToken::issue($this->client(), $this->member(), 'mcp');

        $this->assertNotSame($issued['access'], $issued['refresh']);
        $this->assertNull(OAuthToken::findByAccessToken($issued['refresh']));
        $this->assertNull(OAuthToken::findByRefreshToken($issued['access']));
    }

    public function testRevokedTokenStopsWorking(): void
    {
        $issued = OAuthToken::issue($this->client(), $this->member(), 'mcp');
        $issued['token']->revoke();

        $this->assertNull(OAuthToken::findByAccessToken($issued['access']));
        $this->assertNull(OAuthToken::findByRefreshToken($issued['refresh']));
    }

    public function testExpiredTokenStopsWorking(): void
    {
        Config::modify()->set(OAuthToken::class, 'lifetime', 60);
        $issued = OAuthToken::issue($this->client(), $this->member(), 'mcp');

        DBDatetime::set_mock_now(date('Y-m-d H:i:s', time() + 120));
        $this->assertNull(OAuthToken::findByAccessToken($issued['access']));
        DBDatetime::clear_mock_now();
    }

    public function testUnknownTokensResolveToNothing(): void
    {
        $this->assertNull(OAuthToken::findByAccessToken('not-a-token'));
        $this->assertNull(OAuthCode::findByPlainCode('not-a-code'));
        $this->assertNull(OAuthClient::findByIdentifier('not-a-client'));
    }
}
