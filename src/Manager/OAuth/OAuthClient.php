<?php

namespace Atwx\SilverGateApi\Manager\OAuth;

use SilverStripe\Forms\FieldList;
use SilverStripe\ORM\DataObject;
use SilverStripe\Security\Permission;

/**
 * An MCP client registered through RFC 7591 dynamic client registration.
 *
 * Clients are public: they authenticate with PKCE rather than a secret, which
 * is what the MCP clients in the wild do.
 */
class OAuthClient extends DataObject
{
    private static string $table_name = 'SilverGateApi_OAuthClient';

    private static array $db = [
        'ClientIdentifier' => 'Varchar(64)',
        'Name' => 'Varchar(255)',
        'RedirectUris' => 'Text',
        'LastUsed' => 'Datetime',
    ];

    private static array $has_many = [
        'Codes' => OAuthCode::class,
        'Tokens' => OAuthToken::class,
    ];

    private static array $indexes = [
        'ClientIdentifier' => ['type' => 'unique', 'columns' => ['ClientIdentifier']],
    ];

    private static array $summary_fields = [
        'Name' => 'Name',
        'ClientIdentifier' => 'Client ID',
        'LastUsed.Nice' => 'Last used',
    ];

    private static string $default_sort = 'LastUsed DESC, ID DESC';

    private static string $singular_name = 'MCP client';
    private static string $plural_name = 'MCP clients';

    /**
     * @param string[] $redirectUris
     */
    public static function register(string $name, array $redirectUris): static
    {
        $client = static::create();
        $client->ClientIdentifier = bin2hex(random_bytes(16));
        $client->Name = $name ?: 'Unnamed client';
        $client->applyRedirectUris($redirectUris);
        $client->write();

        return $client;
    }

    public static function findByIdentifier(string $identifier): ?static
    {
        return static::get()->filter('ClientIdentifier', $identifier)->first();
    }

    /**
     * Not setRedirectUris(): that name is the magic setter for the DB field of
     * the same name, so every internal write would route through here.
     *
     * @param string[] $uris
     */
    public function applyRedirectUris(array $uris): void
    {
        $this->RedirectUris = json_encode(array_values(array_unique($uris)));
    }

    /**
     * @return string[]
     */
    public function getRedirectUriList(): array
    {
        $decoded = json_decode((string) $this->RedirectUris, true);

        return is_array($decoded) ? $decoded : [];
    }

    /**
     * Exact string match. Prefix matching would let a registered client
     * redirect a code to somewhere it was never granted.
     */
    public function allowsRedirectUri(string $uri): bool
    {
        return in_array($uri, $this->getRedirectUriList(), true);
    }

    public function getCMSFields(): FieldList
    {
        $fields = parent::getCMSFields();
        $fields->removeByName(['Codes', 'RedirectUris']);

        return $fields;
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
