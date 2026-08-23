<?php

namespace Atwx\SilverGateApi\Manager\Extensions;

use Atwx\SilverGateApi\Exceptions\ApiException;
use Atwx\SilverGateApi\Manager\Services\SiteApiClient;
use Atwx\SilverGateManager\Models\ManagedSite;
use LeKoala\CmsActions\CustomAction;
use SilverStripe\Core\Extension;
use SilverStripe\Forms\FieldList;
use SilverStripe\Forms\LiteralField;

/**
 * Adds the API calling side to ManagedSite, so the manager gains the ability
 * without the manager module having to know the API exists.
 *
 * @extends Extension<ManagedSite>
 */
class ManagedSiteExtension extends Extension
{
    /**
     * Call one API action on this site.
     *
     * @param array<string, mixed> $payload
     * @param array<string, mixed> $claims
     * @return array<string, mixed>
     */
    public function callApi(string $action, array $payload = [], array $claims = []): array
    {
        return SiteApiClient::singleton()->call($this->owner, $action, $payload, $claims);
    }

    protected function updateCMSFields(FieldList $fields): void
    {
        if (!$this->owner->isInDB()) {
            return;
        }

        $fields->addFieldToTab('Root.Help', LiteralField::create(
            'GateApiHelp',
            '<p>To let this manager read and write content on the site, install '
            . '<code>atwx/silverstripe-gate-api</code> there. It reuses the public key above, '
            . 'so no further configuration is needed.</p>'
        ));
    }

    protected function updateCMSActions($actions): void
    {
        if (!$this->owner->isInDB() || !class_exists(CustomAction::class)) {
            return;
        }

        $actions->push(
            CustomAction::create('doTestGateApi', 'Test API')
                ->setShouldRefresh(false)
        );
    }

    /**
     * Reports whether the site answers, and as whom.
     */
    public function doTestGateApi(): string
    {
        try {
            $result = SiteApiClient::singleton()->ping($this->owner);
        } catch (ApiException $e) {
            return 'API unreachable: ' . $e->getMessage();
        }

        return sprintf(
            'API reachable. Acting as %s, scope %s.',
            $result['member'] ?? 'unknown',
            $result['scope'] ?? 'unknown'
        );
    }
}
