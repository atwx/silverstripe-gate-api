<?php

namespace Atwx\SilverGateApi\Manager\Controllers;

use SilverStripe\Control\Controller;
use SilverStripe\Control\Director;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Control\HTTPResponse;

/**
 * The .well-known documents an MCP client reads before it can authenticate:
 * RFC 9728 for the protected resource, RFC 8414 for the authorization server.
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

    /**
     * The routing rules carry the document in an Action route param. Dispatch
     * on it here rather than relying on it reaching handleAction, because the
     * rules match a fixed path with nothing left for url_handlers to read.
     */
    public function index(HTTPRequest $request): HTTPResponse
    {
        $document = (string) $request->param('Action');

        if ($document === '') {
            $document = str_contains($request->getURL(), 'protected-resource')
                ? 'protectedResource'
                : 'authorizationServer';
        }

        return $document === 'protectedResource'
            ? $this->protectedResource()
            : $this->authorizationServer();
    }

    private function authorizationServer(): HTTPResponse
    {
        return $this->json(OAuthController::metadata());
    }

    private function protectedResource(): HTTPResponse
    {
        $base = rtrim(Director::absoluteBaseURL(), '/');

        return $this->json([
            'resource' => $base . '/_silvergatemcp',
            'authorization_servers' => [$base],
            'scopes_supported' => [OAuthController::SCOPE_READ, OAuthController::SCOPE_WRITE],
            'bearer_methods_supported' => ['header'],
        ]);
    }

    /**
     * @param array<string, mixed> $data
     */
    private function json(array $data): HTTPResponse
    {
        $response = HTTPResponse::create(json_encode($data, JSON_UNESCAPED_SLASHES));
        $response->addHeader('Content-Type', 'application/json');
        // Clients cache these; a short window keeps a rename from sticking.
        $response->addHeader('Cache-Control', 'public, max-age=300');

        return $response;
    }
}
