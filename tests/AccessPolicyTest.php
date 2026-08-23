<?php

namespace Atwx\SilverGateApi\Tests;

use Atwx\SilverGateApi\Exceptions\ApiException;
use Atwx\SilverGateApi\Site\Services\AccessPolicy;
use Atwx\SilverGateApi\Site\Services\AuthContext;
use SilverStripe\Core\Config\Config;
use SilverStripe\Dev\SapphireTest;
use SilverStripe\Security\Group;
use SilverStripe\Security\Member;
use SilverStripe\SiteConfig\SiteConfig;

class AccessPolicyTest extends SapphireTest
{
    protected $usesDatabase = false;

    private function context(?array $classes = null): AuthContext
    {
        return new AuthContext(Member::create(), AuthContext::SCOPE_READ, $classes);
    }

    public function testResolvesFullyQualifiedName(): void
    {
        $policy = AccessPolicy::create();

        $this->assertSame(
            SiteConfig::class,
            $policy->resolveClass(SiteConfig::class, $this->context())
        );
    }

    public function testResolvesShortName(): void
    {
        $policy = AccessPolicy::create();

        $this->assertSame(
            SiteConfig::class,
            $policy->resolveClass('SiteConfig', $this->context())
        );
    }

    public function testUnknownClassIsRejected(): void
    {
        $this->expectException(ApiException::class);

        AccessPolicy::create()->resolveClass('NoSuchThing', $this->context());
    }

    public function testDeniedClassesAreUnreachable(): void
    {
        Config::modify()->set(AccessPolicy::class, 'denied_classes', [Member::class]);

        $this->assertFalse(AccessPolicy::create()->isReachable(Member::class, $this->context()));
    }

    public function testDeniedClassesCoverSubclasses(): void
    {
        Config::modify()->set(AccessPolicy::class, 'denied_classes', [Member::class]);

        $this->assertFalse(
            AccessPolicy::create()->isReachable(TestMemberSubclass::class, $this->context())
        );
    }

    public function testAllowListExcludesEverythingElse(): void
    {
        Config::modify()->set(AccessPolicy::class, 'allowed_classes', [SiteConfig::class]);
        $policy = AccessPolicy::create();

        $this->assertTrue($policy->isReachable(SiteConfig::class, $this->context()));
        $this->assertFalse($policy->isReachable(Group::class, $this->context()));
    }

    public function testTokenClaimNarrowsFurther(): void
    {
        $policy = AccessPolicy::create();

        $this->assertTrue($policy->isReachable(SiteConfig::class, $this->context(['SiteConfig'])));
        $this->assertFalse($policy->isReachable(Group::class, $this->context(['SiteConfig'])));
    }

    public function testTokenClaimCannotWidenTheAllowList(): void
    {
        Config::modify()->set(AccessPolicy::class, 'allowed_classes', [SiteConfig::class]);

        $this->assertFalse(
            AccessPolicy::create()->isReachable(Group::class, $this->context(['Group']))
        );
    }

    public function testDenyBeatsBothAllowListAndClaim(): void
    {
        Config::modify()->set(AccessPolicy::class, 'denied_classes', [Group::class]);
        Config::modify()->set(AccessPolicy::class, 'allowed_classes', [Group::class]);

        $this->assertFalse(
            AccessPolicy::create()->isReachable(Group::class, $this->context(['Group']))
        );
    }

    public function testNonDataObjectIsUnreachable(): void
    {
        $this->assertFalse(AccessPolicy::create()->isReachable(self::class, $this->context()));
    }
}
