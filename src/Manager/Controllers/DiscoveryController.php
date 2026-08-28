<?php

namespace Atwx\SilverGateApi\Manager\Controllers;

use Atwx\SilverGateManager\Controllers\OAuthController;
use SilverStripe\Control\Controller;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Control\HTTPResponse;

/**
 * RFC 9728, the document naming the MCP endpoint as a protected resource and
 * pointing at the authorization server that guards it.
 *
 * That server is gate-manager's, and it describes itself under
 * .well-known/oauth-authorization-server.
 */
class DiscoveryController extends Controller
{
    private static array $allowed_actions = [
        'index',
    ];

    protected function init(): void
    {
        Controller::init();
    }

    public function index(HTTPRequest $request): HTTPResponse
    {
        $response = HTTPResponse::create(json_encode([
            'resource' => OAuthController::endpoint('_silvergatemcp'),
            'authorization_servers' => [OAuthController::issuer()],
            'scopes_supported' => [OAuthController::SCOPE_READ, OAuthController::SCOPE_WRITE],
            'bearer_methods_supported' => ['header'],
        ], JSON_UNESCAPED_SLASHES));

        $response->addHeader('Content-Type', 'application/json');
        // Clients cache these; a short window keeps a rename from sticking.
        $response->addHeader('Cache-Control', 'public, max-age=300');

        return $response;
    }
}
