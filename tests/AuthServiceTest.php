<?php

namespace Atwx\SilverGateApi\Tests;

use Atwx\SilverGateApi\Exceptions\ApiException;
use Atwx\SilverGateApi\Site\Services\AuthContext;
use Atwx\SilverGateApi\Site\Services\AuthService;
use Atwx\SilverGateClient\Services\LoginService;
use Atwx\SilverGateClient\Services\TokenService;
use Firebase\JWT\JWT;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Core\Config\Config;
use SilverStripe\Core\Environment;
use SilverStripe\Dev\SapphireTest;
use SilverStripe\Security\DefaultAdminService;
use SilverStripe\Security\Member;

class AuthServiceTest extends SapphireTest
{
    protected static $fixture_file = 'AuthServiceTest.yml';

    private static ?string $privateKey = null;
    private static ?string $publicKey = null;

    private mixed $originalEnvKey = null;

    protected function setUp(): void
    {
        parent::setUp();

        // TokenService prefers SILVERGATECLIENT_PUBLIC_KEY over the config, so a
        // site that sets it would otherwise override the key under test.
        $this->originalEnvKey = Environment::getEnv('SILVERGATECLIENT_PUBLIC_KEY');
        Environment::setEnv('SILVERGATECLIENT_PUBLIC_KEY', '');

        if (!self::$privateKey) {
            $resource = openssl_pkey_new([
                'private_key_bits' => 2048,
                'private_key_type' => OPENSSL_KEYTYPE_RSA,
            ]);
            openssl_pkey_export($resource, self::$privateKey);
            self::$publicKey = openssl_pkey_get_details($resource)['key'];
        }

        Config::modify()->set(TokenService::class, 'public_key', self::$publicKey);
        // The fixture member stands in for a dedicated content account.
        Config::modify()->set(LoginService::class, 'login_as_default_admin', false);
        Config::modify()->set(LoginService::class, 'member_email', 'fallback@example.com');
    }

    protected function tearDown(): void
    {
        Environment::setEnv('SILVERGATECLIENT_PUBLIC_KEY', $this->originalEnvKey ?: '');
        parent::tearDown();
    }

    private function token(array $claims = []): string
    {
        return JWT::encode(
            array_merge(['iat' => time(), 'exp' => time() + 60], $claims),
            self::$privateKey,
            'RS256'
        );
    }

    private function request(?string $token): HTTPRequest
    {
        $request = new HTTPRequest('POST', '/_silvergateapi/ping');

        if ($token !== null) {
            $request->addHeader('authorization', 'Bearer ' . $token);
        }

        return $request;
    }

    public function testDefaultsToReadScopeAndConfiguredMember(): void
    {
        $context = AuthService::create()->authenticate($this->request($this->token()));

        $this->assertSame('fallback@example.com', $context->getMember()->Email);
        $this->assertSame(AuthContext::SCOPE_READ, $context->getScope());
        $this->assertFalse($context->canWrite());
        $this->assertNull($context->getClasses());
    }

    public function testSubjectClaimSelectsMemberByEmail(): void
    {
        $context = AuthService::create()->authenticate(
            $this->request($this->token(['sub' => 'editor@example.com']))
        );

        $this->assertSame('editor@example.com', $context->getMember()->Email);
    }

    public function testSubjectClaimSelectsMemberById(): void
    {
        $id = $this->idFromFixture(Member::class, 'editor');

        $context = AuthService::create()->authenticate(
            $this->request($this->token(['sub' => (string) $id]))
        );

        $this->assertSame($id, $context->getMember()->ID);
    }

    public function testUnknownSubjectFallsBackToTheConfiguredMember(): void
    {
        $context = AuthService::create()->authenticate(
            $this->request($this->token(['sub' => 'nobody@example.com']))
        );

        $this->assertSame('fallback@example.com', $context->getMember()->Email);
    }

    public function testUnknownSubjectFallsBackToTheDefaultAdmin(): void
    {
        // Nothing configured, so the gate client's own default applies.
        Config::modify()->set(LoginService::class, 'member_email', null);
        Config::modify()->set(LoginService::class, 'login_as_default_admin', true);
        DefaultAdminService::clearDefaultAdmin();
        DefaultAdminService::setDefaultAdmin('admin@example.com', 'secret');

        $context = AuthService::create()->authenticate(
            $this->request($this->token(['sub' => 'nobody@example.com']))
        );

        $this->assertSame('admin@example.com', $context->getMember()->Email);
    }

    public function testUnknownSubjectIsRejectedWhenNoDefaultMemberExists(): void
    {
        Config::modify()->set(LoginService::class, 'member_email', null);
        Config::modify()->set(LoginService::class, 'login_as_default_admin', false);

        $this->expectException(ApiException::class);

        AuthService::create()->authenticate(
            $this->request($this->token(['sub' => 'nobody@example.com']))
        );
    }

    public function testWriteScopeIsCarried(): void
    {
        $context = AuthService::create()->authenticate(
            $this->request($this->token(['scope' => 'write']))
        );

        $this->assertTrue($context->canWrite());
    }

    public function testWriteScopeIsRefusedWhenTheSiteForbidsWrites(): void
    {
        Config::modify()->set(AuthService::class, 'allow_writes', false);

        $this->expectException(ApiException::class);

        AuthService::create()->authenticate($this->request($this->token(['scope' => 'write'])));
    }

    public function testUnknownScopeIsRejected(): void
    {
        $this->expectException(ApiException::class);

        AuthService::create()->authenticate($this->request($this->token(['scope' => 'admin'])));
    }

    public function testClassesClaimIsCarried(): void
    {
        $context = AuthService::create()->authenticate(
            $this->request($this->token(['classes' => ['SiteConfig', 'Group']]))
        );

        $this->assertSame(['SiteConfig', 'Group'], $context->getClasses());
    }

    public function testEmptyClassesClaimIsRejected(): void
    {
        $this->expectException(ApiException::class);

        AuthService::create()->authenticate($this->request($this->token(['classes' => []])));
    }

    public function testMissingHeaderIsRejected(): void
    {
        $this->expectException(ApiException::class);

        AuthService::create()->authenticate($this->request(null));
    }

    public function testTokenSignedWithAnotherKeyIsRejected(): void
    {
        $resource = openssl_pkey_new([
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);
        openssl_pkey_export($resource, $otherKey);

        $foreign = JWT::encode(['iat' => time(), 'exp' => time() + 60], $otherKey, 'RS256');

        $this->expectException(ApiException::class);

        AuthService::create()->authenticate($this->request($foreign));
    }

    public function testExpiredTokenIsRejected(): void
    {
        Config::modify()->set(TokenService::class, 'token_max_age_seconds', 30);

        $stale = $this->token(['iat' => time() - 600, 'exp' => time() + 600]);

        $this->expectException(ApiException::class);

        AuthService::create()->authenticate($this->request($stale));
    }

    public function testBase64EncodedTokenIsAccepted(): void
    {
        $context = AuthService::create()->authenticate(
            $this->request(base64_encode($this->token()))
        );

        $this->assertSame('fallback@example.com', $context->getMember()->Email);
    }
}
