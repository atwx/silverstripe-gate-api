<?php

namespace Atwx\SilverGateApi\Manager\OAuth;

use SilverStripe\ORM\DataObject;
use SilverStripe\ORM\FieldType\DBDatetime;
use SilverStripe\Security\Member;
use SilverStripe\Security\Permission;

/**
 * An access token, plus its refresh token. Both are stored as hashes.
 */
class OAuthToken extends DataObject
{
    private static string $table_name = 'SilverGateApi_OAuthToken';

    private static array $db = [
        'AccessTokenHash' => 'Varchar(64)',
        'RefreshTokenHash' => 'Varchar(64)',
        'Scope' => 'Varchar(255)',
        'ExpiresAt' => 'Datetime',
        'RevokedAt' => 'Datetime',
        'LastUsed' => 'Datetime',
    ];

    private static array $has_one = [
        'Client' => OAuthClient::class,
        'Member' => Member::class,
    ];

    private static array $indexes = [
        'AccessTokenHash' => ['type' => 'index', 'columns' => ['AccessTokenHash']],
        'RefreshTokenHash' => ['type' => 'index', 'columns' => ['RefreshTokenHash']],
    ];

    private static array $summary_fields = [
        'Member.Email' => 'Member',
        'Client.Name' => 'Client',
        'Scope' => 'Scope',
        'ExpiresAt.Nice' => 'Expires',
        'LastUsed.Nice' => 'Last used',
    ];

    private static string $default_sort = 'LastUsed DESC, ID DESC';

    private static string $singular_name = 'MCP token';
    private static string $plural_name = 'MCP tokens';

    /**
     * Seconds an access token stays valid. The client refreshes after that.
     *
     * @config
     */
    private static int $lifetime = 3600;

    /**
     * @return array{token: static, access: string, refresh: string}
     */
    public static function issue(OAuthClient $client, Member $member, string $scope): array
    {
        $access = bin2hex(random_bytes(32));
        $refresh = bin2hex(random_bytes(32));

        $token = static::create();
        $token->AccessTokenHash = hash('sha256', $access);
        $token->RefreshTokenHash = hash('sha256', $refresh);
        $token->Scope = $scope;
        $token->ClientID = $client->ID;
        $token->MemberID = $member->ID;
        $token->ExpiresAt = date('Y-m-d H:i:s', DBDatetime::now()->getTimestamp() + static::config()->get('lifetime'));
        $token->write();

        return ['token' => $token, 'access' => $access, 'refresh' => $refresh];
    }

    public static function findByAccessToken(string $plain): ?static
    {
        $token = static::get()->filter('AccessTokenHash', hash('sha256', $plain))->first();

        return $token?->isUsable() ? $token : null;
    }

    public static function findByRefreshToken(string $plain): ?static
    {
        $token = static::get()->filter('RefreshTokenHash', hash('sha256', $plain))->first();

        return $token && !$token->RevokedAt ? $token : null;
    }

    public function isUsable(): bool
    {
        if ($this->RevokedAt) {
            return false;
        }

        return strtotime((string) $this->ExpiresAt) > DBDatetime::now()->getTimestamp();
    }

    public function touch(): void
    {
        $this->LastUsed = DBDatetime::now()->Rfc2822();
        $this->write();
    }

    public function revoke(): void
    {
        $this->RevokedAt = DBDatetime::now()->Rfc2822();
        $this->write();
    }

    public function getLifetimeSeconds(): int
    {
        return max(0, strtotime((string) $this->ExpiresAt) - DBDatetime::now()->getTimestamp());
    }

    public function canView($member = null): bool
    {
        return Permission::check('ADMIN', 'any', $member);
    }

    public function canEdit($member = null): bool
    {
        return false;
    }

    public function canCreate($member = null, $context = []): bool
    {
        return false;
    }

    public function canDelete($member = null): bool
    {
        return Permission::check('ADMIN', 'any', $member);
    }
}
