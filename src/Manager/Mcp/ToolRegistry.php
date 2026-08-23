<?php

namespace Atwx\SilverGateApi\Manager\Mcp;

use Atwx\SilverGateApi\Exceptions\ApiException;
use Atwx\SilverGateApi\Manager\Services\SiteApiClient;
use SilverStripe\Core\Extensible;
use SilverStripe\Core\Injector\Injectable;
use SilverStripe\Security\Member;

/**
 * The tools the MCP endpoint exposes.
 *
 * Everything except sites_list is a thin pass through to one action of the site
 * API, with the site resolved and the token minted here. Keeping the mapping
 * declarative means the tool list and the dispatcher cannot drift apart.
 */
class ToolRegistry
{
    use Injectable;
    use Extensible;

    /**
     * action => [writes, description, extra properties, required]
     */
    private const ACTIONS = [
        'classes' => [
            false,
            'List the DataObject classes available on a site. Use this to discover what a site holds.',
            ['search' => ['type' => 'string', 'description' => 'Filter by partial class name']],
            [],
        ],
        'schema' => [
            false,
            'Describe one class: field types, valid Enum values and relations. '
            . 'Call this before create or update.',
            [
                'class' => [
                    'type' => 'string',
                    'description' => 'Class name, fully qualified or a unique short name',
                ],
            ],
            ['class'],
        ],
        'query' => [
            false,
            'Query records of a class.',
            [
                'class' => ['type' => 'string'],
                'filter' => [
                    'type' => 'object',
                    'description' => 'ORM filter, e.g. {"Title:PartialMatch": "news"}',
                ],
                'sort' => ['type' => 'string', 'description' => 'e.g. "Created DESC"'],
                'limit' => ['type' => 'integer', 'description' => 'Max 100, default 20'],
                'offset' => ['type' => 'integer'],
                'stage' => [
                    'type' => 'string',
                    'enum' => ['draft', 'live'],
                    'description' => 'Versioned classes only, default draft',
                ],
            ],
            ['class'],
        ],
        'get' => [
            false,
            'Read one record by ID, including the IDs on its relations.',
            [
                'class' => ['type' => 'string'],
                'id' => ['type' => 'integer'],
                'stage' => ['type' => 'string', 'enum' => ['draft', 'live']],
            ],
            ['class', 'id'],
        ],
        'create' => [
            true,
            'Create a record. Versioned records are written to draft; publish separately. '
            . 'Relations take an array of IDs.',
            [
                'class' => ['type' => 'string'],
                'fields' => [
                    'type' => 'object',
                    'description' => 'Field values, e.g. {"Title": "...", "Speakers": [1,2]}',
                ],
            ],
            ['class', 'fields'],
        ],
        'update' => [
            true,
            'Change fields on a record. Setting a relation replaces it entirely.',
            [
                'class' => ['type' => 'string'],
                'id' => ['type' => 'integer'],
                'fields' => ['type' => 'object'],
            ],
            ['class', 'id', 'fields'],
        ],
        'delete' => [
            true,
            'Delete a record. This cannot be undone.',
            ['class' => ['type' => 'string'], 'id' => ['type' => 'integer']],
            ['class', 'id'],
        ],
        'publish' => [
            true,
            'Publish the draft version of a versioned record.',
            ['class' => ['type' => 'string'], 'id' => ['type' => 'integer']],
            ['class', 'id'],
        ],
        'unpublish' => [
            true,
            'Remove a versioned record from the live stage. The draft stays.',
            ['class' => ['type' => 'string'], 'id' => ['type' => 'integer']],
            ['class', 'id'],
        ],
    ];

    /**
     * @return array<int, array<string, mixed>>
     */
    public function listTools(Member $member, bool $mayWrite): array
    {
        $tools = [[
            'name' => 'sites_list',
            'description' => 'List the sites you may reach. Call this first: every other tool needs a site.',
            'inputSchema' => ['type' => 'object', 'properties' => (object) [], 'required' => []],
        ]];

        foreach (self::ACTIONS as $action => [$writes, $description, $properties, $required]) {
            if ($writes && !$mayWrite) {
                continue;
            }

            $tools[] = [
                'name' => 'site_' . $action,
                'description' => $description,
                'inputSchema' => [
                    'type' => 'object',
                    'properties' => array_merge(
                        ['site' => [
                            'type' => 'string',
                            'description' => 'Domain of the site, from sites_list',
                        ]],
                        $properties
                    ),
                    'required' => array_merge(['site'], $required),
                ],
            ];
        }

        $this->extend('updateTools', $tools, $member, $mayWrite);

        return $tools;
    }

    /**
     * @param array<string, mixed> $arguments
     * @return array<string, mixed>
     */
    public function call(string $name, array $arguments, Member $member, bool $mayWrite): array
    {
        if ($name === 'sites_list') {
            return $this->listSites($member, $mayWrite);
        }

        $action = str_starts_with($name, 'site_') ? substr($name, 5) : '';

        if (!isset(self::ACTIONS[$action])) {
            throw new ApiException(sprintf('Unknown tool "%s".', $name), 404);
        }

        [$writes] = self::ACTIONS[$action];

        if ($writes && !$mayWrite) {
            throw new ApiException('This connection was authorised for reading only.', 403);
        }

        $domain = trim((string) ($arguments['site'] ?? ''));

        if ($domain === '') {
            throw new ApiException('"site" is required. Call sites_list to see what you may reach.', 400);
        }

        $scope = $writes ? SitePolicy::SCOPE_WRITE : SitePolicy::SCOPE_READ;
        $site = SitePolicy::singleton()->resolve($domain, $member, $scope);

        if (!$site) {
            throw new ApiException(sprintf('No site "%s" that you may access.', $domain), 403);
        }

        unset($arguments['site']);

        return SiteApiClient::singleton()->call($site, $action, $arguments, [
            'sub' => $member->Email,
            'scope' => $scope,
        ]);
    }

    /**
     * @return array<string, mixed>
     */
    private function listSites(Member $member, bool $mayWrite): array
    {
        $sites = [];

        foreach (SitePolicy::singleton()->accessibleSites($member) as $site) {
            $sites[] = [
                'site' => $site->Domain,
                'writable' => $mayWrite
                    && SitePolicy::singleton()->canAccess($site, $member, SitePolicy::SCOPE_WRITE),
            ];
        }

        return ['sites' => $sites];
    }
}
