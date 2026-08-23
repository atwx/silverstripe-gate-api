<?php

namespace Atwx\SilverGateApi\Site\Services;

use SilverStripe\Security\Member;

/**
 * The result of authenticating one request: who is acting, and what the token
 * allows them to do.
 */
class AuthContext
{
    public const SCOPE_READ = 'read';
    public const SCOPE_WRITE = 'write';

    private Member $member;
    private string $scope;

    /** @var string[]|null Class names the token is limited to, null means no limit. */
    private ?array $classes;

    /**
     * @param string[]|null $classes
     */
    public function __construct(Member $member, string $scope, ?array $classes = null)
    {
        $this->member = $member;
        $this->scope = $scope;
        $this->classes = $classes;
    }

    public function getMember(): Member
    {
        return $this->member;
    }

    public function getScope(): string
    {
        return $this->scope;
    }

    public function canWrite(): bool
    {
        return $this->scope === self::SCOPE_WRITE;
    }

    /**
     * @return string[]|null
     */
    public function getClasses(): ?array
    {
        return $this->classes;
    }
}
