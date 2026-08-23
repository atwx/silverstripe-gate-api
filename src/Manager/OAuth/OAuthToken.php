<?php

namespace Atwx\SilverGateApi\Manager\OAuth;

use SilverStripe\ORM\DataObject;
use SilverStripe\ORM\FieldType\DBDatetime;
use SilverStripe\Security\Member;
use SilverStripe\Security\Permission;

/**
 * An access token, plus its refresh token. Both are stored as hashes.
 *
 * Refreshing rotates the pair: the old row is revoked and a new one issued,
 * carrying the chain's original start forward. Three things end a chain:
 *
 *   - the access token's own hour, after which the client must refresh
 *   - refresh_idle_lifetime, if nobody refreshes for that long
 *   - refresh_absolute_lifetime, counted from the original authorisation,
 *     after which the user logs in again no matter how active the client was
 */
class OAuthToken extends DataObject
{
    private static string $table_name = 'SilverGateApi_OAuthToken';

    private static array $db = [
        'AccessTokenHash' => 'Varchar(64)',
        'RefreshTokenHash' => 'Varchar(64)',
        'Scope' => 'Varchar(255)',
        'ExpiresAt' => 'Datetime',
        'RefreshExpiresAt' => 'Datetime',
        'ChainStartedAt' => 'Datetime',
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
        'ExpiresAt.Nice' => 'Access expires',
        'RefreshExpiresAt.Nice' => 'Refresh expires',
        'ChainStartedAt.Nice' => 'Signed in',
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
     * Seconds a refresh token survives without being used. 14 days.
     *
     * @config
     */
    private static int $refresh_idle_lifetime = 1209600;

    /**
     * Seconds from the original authorisation after which the chain ends,
     * however active it has been. 30 days.
     *
     * @config
     */
    private static int $refresh_absolute_lifetime = 2592000;

    /**
     * @return array{token: static, access: string, refresh: string}
     */
    public static function issue(
        OAuthClient $client,
        Member $member,
        string $scope,
        ?string $chainStartedAt = null
    ): array {
        $access = bin2hex(random_bytes(32));
        $refresh = bin2hex(random_bytes(32));
        $now = DBDatetime::now()->getTimestamp();

        $token = static::create();
        $token->AccessTokenHash = hash('sha256', $access);
        $token->RefreshTokenHash = hash('sha256', $refresh);
        $token->Scope = $scope;
        $token->ClientID = $client->ID;
        $token->MemberID = $member->ID;
        $token->ExpiresAt = date('Y-m-d H:i:s', $now + static::config()->get('lifetime'));
        $token->RefreshExpiresAt = date(
            'Y-m-d H:i:s',
            $now + static::config()->get('refresh_idle_lifetime')
        );
        // A rotation continues the chain rather than starting a new one, so the
        // absolute limit cannot be pushed out by refreshing forever.
        $token->ChainStartedAt = $chainStartedAt ?: date('Y-m-d H:i:s', $now);
        $token->write();

        return ['token' => $token, 'access' => $access, 'refresh' => $refresh];
    }

    public static function findByAccessToken(string $plain): ?static
    {
        $token = static::get()->filter('AccessTokenHash', hash('sha256', $plain))->first();

        return $token?->isUsable() ? $token : null;
    }

    /**
     * Returns the row whatever state it is in, so the caller can tell a spent
     * token apart from one that was never issued. That difference matters:
     * presenting an already rotated refresh token means someone kept a copy.
     */
    public static function lookupRefreshToken(string $plain): ?static
    {
        return static::get()->filter('RefreshTokenHash', hash('sha256', $plain))->first();
    }

    public function isUsable(): bool
    {
        if ($this->RevokedAt) {
            return false;
        }

        return strtotime((string) $this->ExpiresAt) > DBDatetime::now()->getTimestamp();
    }

    public function isRefreshUsable(): bool
    {
        if ($this->RevokedAt) {
            return false;
        }

        $now = DBDatetime::now()->getTimestamp();

        if ($this->RefreshExpiresAt && strtotime((string) $this->RefreshExpiresAt) <= $now) {
            return false;
        }

        return !$this->isChainExpired();
    }

    public function isChainExpired(): bool
    {
        if (!$this->ChainStartedAt) {
            return false;
        }

        $limit = static::config()->get('refresh_absolute_lifetime');

        if ($limit <= 0) {
            return false;
        }

        return strtotime((string) $this->ChainStartedAt) + $limit <= DBDatetime::now()->getTimestamp();
    }

    public function touch(): void
    {
        $this->LastUsed = DBDatetime::now()->Rfc2822();
        $this->write();
    }

    public function revoke(): void
    {
        if ($this->RevokedAt) {
            return;
        }

        $this->RevokedAt = DBDatetime::now()->Rfc2822();
        $this->write();
    }

    /**
     * Revokes every token this client holds for this member.
     *
     * Used when a spent refresh token turns up again: at that point either the
     * client or an attacker is holding a copy, and there is no way to tell
     * which, so the safe move is to end the whole grant and make the user log
     * in again.
     */
    public function revokeChain(): int
    {
        $tokens = static::get()->filter([
            'ClientID' => $this->ClientID,
            'MemberID' => $this->MemberID,
            'RevokedAt' => null,
        ]);

        $count = 0;
        foreach ($tokens as $token) {
            $token->revoke();
            $count++;
        }

        return $count;
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
