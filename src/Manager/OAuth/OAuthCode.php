<?php

namespace Atwx\SilverGateApi\Manager\OAuth;

use SilverStripe\ORM\DataObject;
use SilverStripe\ORM\FieldType\DBDatetime;
use SilverStripe\Security\Member;
use SilverStripe\Security\Permission;

/**
 * A single use authorization code, bound to a PKCE challenge.
 *
 * Only the hash of the code is stored, so a database leak does not hand out
 * usable codes.
 */
class OAuthCode extends DataObject
{
    private static string $table_name = 'SilverGateApi_OAuthCode';

    private static array $db = [
        'CodeHash' => 'Varchar(64)',
        'CodeChallenge' => 'Varchar(128)',
        'RedirectUri' => 'Varchar(2000)',
        'Scope' => 'Varchar(255)',
        'ExpiresAt' => 'Datetime',
        'UsedAt' => 'Datetime',
    ];

    private static array $has_one = [
        'Client' => OAuthClient::class,
        'Member' => Member::class,
    ];

    private static array $indexes = [
        'CodeHash' => ['type' => 'unique', 'columns' => ['CodeHash']],
    ];

    /**
     * Seconds a code stays usable. Short: the client redeems it immediately.
     *
     * @config
     */
    private static int $lifetime = 120;

    /**
     * Creates a code and returns the plain text value, which is never stored.
     */
    public static function issue(
        OAuthClient $client,
        Member $member,
        string $codeChallenge,
        string $redirectUri,
        string $scope
    ): string {
        $plain = bin2hex(random_bytes(32));

        $code = static::create();
        $code->CodeHash = hash('sha256', $plain);
        $code->CodeChallenge = $codeChallenge;
        $code->RedirectUri = $redirectUri;
        $code->Scope = $scope;
        $code->ClientID = $client->ID;
        $code->MemberID = $member->ID;
        $code->ExpiresAt = date('Y-m-d H:i:s', DBDatetime::now()->getTimestamp() + static::config()->get('lifetime'));
        $code->write();

        return $plain;
    }

    public static function findByPlainCode(string $plain): ?static
    {
        return static::get()->filter('CodeHash', hash('sha256', $plain))->first();
    }

    public function isUsable(): bool
    {
        if ($this->UsedAt) {
            return false;
        }

        return strtotime((string) $this->ExpiresAt) > DBDatetime::now()->getTimestamp();
    }

    /**
     * Verifies the PKCE verifier against the stored S256 challenge.
     */
    public function matchesVerifier(string $verifier): bool
    {
        $expected = rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');

        return hash_equals((string) $this->CodeChallenge, $expected);
    }

    /**
     * Marks the code spent. Any later attempt to redeem it fails, which is what
     * makes replay of an intercepted code useless.
     */
    public function consume(): void
    {
        $this->UsedAt = DBDatetime::now()->Rfc2822();
        $this->write();
    }

    public static function pruneExpired(): void
    {
        foreach (static::get()->filter('ExpiresAt:LessThan', DBDatetime::now()->Rfc2822()) as $code) {
            $code->delete();
        }
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
}
