<?php

namespace Atwx\SilverGateApi\Manager\Mcp;

use Atwx\SilverGateManager\Models\ManagedSite;
use SilverStripe\Core\Config\Configurable;
use SilverStripe\Core\Extensible;
use SilverStripe\Core\Injector\Injectable;
use SilverStripe\Model\List\ArrayList;
use SilverStripe\Security\Member;

/**
 * Decides which managed sites a member may reach through MCP, and whether they
 * may write.
 *
 * The default is the manager's own rule: if you may use SilverGate to log into
 * a site, you may read and write it through the API too, because the API grants
 * nothing the browser login would not. Installs with a finer grained model hook
 * into updateSiteAccess to narrow it.
 *
 *     public function updateSiteAccess(bool &$allowed, ManagedSite $site, Member $member, string $scope)
 *     {
 *         $allowed = $allowed && $this->mySiteRule($site, $member, $scope);
 *     }
 */
class SitePolicy
{
    use Configurable;
    use Injectable;
    use Extensible;

    public const SCOPE_READ = 'read';
    public const SCOPE_WRITE = 'write';

    public function canAccess(ManagedSite $site, Member $member, string $scope = self::SCOPE_READ): bool
    {
        $allowed = $site->canLogin($member);

        $this->extend('updateSiteAccess', $allowed, $site, $member, $scope);

        return (bool) $allowed;
    }

    /**
     * Sites the member may reach, for the sites listing.
     */
    public function accessibleSites(Member $member, string $scope = self::SCOPE_READ): ArrayList
    {
        $sites = ArrayList::create();

        foreach (ManagedSite::get() as $site) {
            if ($this->canAccess($site, $member, $scope)) {
                $sites->push($site);
            }
        }

        return $sites;
    }

    /**
     * Resolves a domain to a site the member may reach, or null.
     */
    public function resolve(string $domain, Member $member, string $scope = self::SCOPE_READ): ?ManagedSite
    {
        $site = ManagedSite::getByDomain(strtolower(trim($domain)));

        if (!$site || !$this->canAccess($site, $member, $scope)) {
            return null;
        }

        return $site;
    }
}
