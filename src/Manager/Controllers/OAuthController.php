<?php

namespace Atwx\SilverGateApi\Manager\Controllers;

use Atwx\SilverGateApi\Manager\OAuth\OAuthClient;
use Atwx\SilverGateApi\Manager\OAuth\OAuthCode;
use Atwx\SilverGateApi\Manager\OAuth\OAuthToken;
use SilverStripe\Control\Controller;
use SilverStripe\Control\Director;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Control\HTTPResponse;
use SilverStripe\Security\Member;
use SilverStripe\Security\Security;

/**
 * OAuth 2.1 authorization server for the MCP endpoint.
 *
 * Public clients only: every flow requires PKCE with S256, and no client
 * secrets are issued. That is what the MCP clients expect, and it means a
 * stolen authorization code is useless without the verifier.
 *
 * The user is authenticated by the site's own login, so whoever runs this
 * already decides who may get a token.
 */
class OAuthController extends Controller
{
    private static string $url_segment = '_silvergatemcp/oauth';

    private static array $allowed_actions = [
        'register',
        'authorize',
        'approve',
        'token',
    ];

    private static array $url_handlers = [
        'register' => 'register',
        'authorize' => 'authorize',
        'approve' => 'approve',
        'token' => 'token',
    ];

    /**
     * The scopes a token may carry. "mcp" is read only; "mcp:write" adds the
     * write actions.
     */
    public const SCOPE_READ = 'mcp';
    public const SCOPE_WRITE = 'mcp:write';

    protected function init(): void
    {
        // Controller::init() rather than parent::init() so no CMS login check
        // is imposed on the endpoints that must stay anonymous.
        Controller::init();
    }

    public static function issuer(): string
    {
        return rtrim(Director::absoluteBaseURL(), '/');
    }

    /**
     * RFC 8414 authorization server metadata.
     *
     * @return array<string, mixed>
     */
    public static function metadata(): array
    {
        $base = self::issuer();

        return [
            'issuer' => $base,
            'authorization_endpoint' => $base . '/_silvergatemcp/oauth/authorize',
            'token_endpoint' => $base . '/_silvergatemcp/oauth/token',
            'registration_endpoint' => $base . '/_silvergatemcp/oauth/register',
            'scopes_supported' => [self::SCOPE_READ, self::SCOPE_WRITE],
            'response_types_supported' => ['code'],
            'grant_types_supported' => ['authorization_code', 'refresh_token'],
            'code_challenge_methods_supported' => ['S256'],
            'token_endpoint_auth_methods_supported' => ['none'],
        ];
    }

    /**
     * RFC 7591 dynamic client registration. Open by design: a client gets an
     * identifier, nothing more. Authorisation still happens at /authorize,
     * where a real person has to log in and approve.
     */
    public function register(HTTPRequest $request): HTTPResponse
    {
        if (!$request->isPOST()) {
            return $this->json(['error' => 'invalid_request'], 405);
        }

        $body = json_decode((string) $request->getBody(), true) ?: [];
        $uris = $body['redirect_uris'] ?? [];

        if (!is_array($uris) || !$uris) {
            return $this->json(['error' => 'invalid_redirect_uri'], 400);
        }

        foreach ($uris as $uri) {
            if (!$this->isAcceptableRedirectUri((string) $uri)) {
                return $this->json([
                    'error' => 'invalid_redirect_uri',
                    'error_description' => 'Redirect URIs must be https, a loopback address, or a custom scheme.',
                ], 400);
            }
        }

        $client = OAuthClient::register((string) ($body['client_name'] ?? ''), array_map('strval', $uris));

        return $this->json([
            'client_id' => $client->ClientIdentifier,
            'client_name' => $client->Name,
            'redirect_uris' => $client->getRedirectUriList(),
            'token_endpoint_auth_method' => 'none',
            'grant_types' => ['authorization_code', 'refresh_token'],
            'response_types' => ['code'],
        ], 201);
    }

    /**
     * Shows the consent screen. The site's own login gates it, so an
     * unauthenticated visitor is sent to log in first and comes back here.
     */
    public function authorize(HTTPRequest $request): HTTPResponse|string
    {
        $client = OAuthClient::findByIdentifier((string) $request->getVar('client_id'));
        $redirectUri = (string) $request->getVar('redirect_uri');

        // These two are validated before anything is echoed back to the
        // redirect target, because an attacker controlled URI must never
        // receive an error code.
        if (!$client) {
            return $this->json(['error' => 'invalid_client'], 400);
        }

        if (!$client->allowsRedirectUri($redirectUri)) {
            return $this->json(['error' => 'invalid_redirect_uri'], 400);
        }

        $state = (string) $request->getVar('state');
        $challenge = (string) $request->getVar('code_challenge');
        $method = strtoupper((string) $request->getVar('code_challenge_method'));
        $scope = $this->normaliseScope((string) $request->getVar('scope'));

        if ($method !== 'S256' || $challenge === '') {
            return $this->redirectWithError($redirectUri, 'invalid_request', 'PKCE with S256 is required.', $state);
        }

        if ((string) $request->getVar('response_type') !== 'code') {
            return $this->redirectWithError($redirectUri, 'unsupported_response_type', '', $state);
        }

        $member = Security::getCurrentUser();

        if (!$member) {
            return $this->redirect(
                Security::config()->get('login_url') . '?BackURL=' . urlencode($request->getURL(true))
            );
        }

        return $this->renderWith('Atwx\\SilverGateApi\\McpConsent', [
            'ClientName' => $client->Name,
            'MemberEmail' => $member->Email,
            'RequestsWrite' => $scope === self::SCOPE_WRITE,
            'ClientId' => $client->ClientIdentifier,
            'RedirectUri' => $redirectUri,
            'State' => $state,
            'CodeChallenge' => $challenge,
            'Scope' => $scope,
            'ApproveLink' => Director::absoluteBaseURL() . '_silvergatemcp/oauth/approve',
            'SecurityToken' => $this->getSecurityToken(),
        ]);
    }

    /**
     * Consent submitted. Issues the code and hands control back to the client.
     */
    public function approve(HTTPRequest $request): HTTPResponse
    {
        if (!$request->isPOST()) {
            return $this->json(['error' => 'invalid_request'], 405);
        }

        $member = Security::getCurrentUser();

        if (!$member) {
            return $this->json(['error' => 'access_denied'], 403);
        }

        if (!hash_equals($this->getSecurityToken(), (string) $request->postVar('security_token'))) {
            return $this->json(['error' => 'invalid_request', 'error_description' => 'Bad security token.'], 403);
        }

        $client = OAuthClient::findByIdentifier((string) $request->postVar('client_id'));
        $redirectUri = (string) $request->postVar('redirect_uri');
        $state = (string) $request->postVar('state');

        if (!$client || !$client->allowsRedirectUri($redirectUri)) {
            return $this->json(['error' => 'invalid_client'], 400);
        }

        if (!$request->postVar('approve')) {
            return $this->redirectWithError($redirectUri, 'access_denied', 'The user declined.', $state);
        }

        $code = OAuthCode::issue(
            $client,
            $member,
            (string) $request->postVar('code_challenge'),
            $redirectUri,
            $this->normaliseScope((string) $request->postVar('scope'))
        );

        return $this->redirect($this->appendQuery($redirectUri, array_filter([
            'code' => $code,
            'state' => $state,
        ])));
    }

    /**
     * Exchanges a code or a refresh token for an access token.
     */
    public function token(HTTPRequest $request): HTTPResponse
    {
        if (!$request->isPOST()) {
            return $this->json(['error' => 'invalid_request'], 405);
        }

        return match ((string) $request->postVar('grant_type')) {
            'authorization_code' => $this->exchangeCode($request),
            'refresh_token' => $this->exchangeRefreshToken($request),
            default => $this->json(['error' => 'unsupported_grant_type'], 400),
        };
    }

    private function exchangeCode(HTTPRequest $request): HTTPResponse
    {
        $code = OAuthCode::findByPlainCode((string) $request->postVar('code'));

        if (!$code || !$code->isUsable()) {
            return $this->json(['error' => 'invalid_grant'], 400);
        }

        // Spend the code before anything else can fail, so a failed exchange
        // cannot be retried with a different verifier.
        $code->consume();

        $client = OAuthClient::findByIdentifier((string) $request->postVar('client_id'));

        if (!$client || $client->ID !== $code->ClientID) {
            return $this->json(['error' => 'invalid_client'], 400);
        }

        if ((string) $request->postVar('redirect_uri') !== (string) $code->RedirectUri) {
            return $this->json(['error' => 'invalid_grant', 'error_description' => 'Redirect URI mismatch.'], 400);
        }

        if (!$code->matchesVerifier((string) $request->postVar('code_verifier'))) {
            return $this->json(['error' => 'invalid_grant', 'error_description' => 'PKCE verification failed.'], 400);
        }

        $member = $code->Member();

        if (!$member || !$member->exists()) {
            return $this->json(['error' => 'invalid_grant'], 400);
        }

        $client->LastUsed = date('Y-m-d H:i:s');
        $client->write();

        return $this->tokenResponse(OAuthToken::issue($client, $member, (string) $code->Scope));
    }

    private function exchangeRefreshToken(HTTPRequest $request): HTTPResponse
    {
        $existing = OAuthToken::findByRefreshToken((string) $request->postVar('refresh_token'));

        if (!$existing) {
            return $this->json(['error' => 'invalid_grant'], 400);
        }

        $client = OAuthClient::findByIdentifier((string) $request->postVar('client_id'));

        if (!$client || $client->ID !== $existing->ClientID) {
            return $this->json(['error' => 'invalid_client'], 400);
        }

        $member = $existing->Member();

        if (!$member || !$member->exists()) {
            return $this->json(['error' => 'invalid_grant'], 400);
        }

        // Rotate: the old refresh token stops working once it has been used.
        $existing->revoke();

        return $this->tokenResponse(OAuthToken::issue($client, $member, (string) $existing->Scope));
    }

    /**
     * @param array{token: OAuthToken, access: string, refresh: string} $issued
     */
    private function tokenResponse(array $issued): HTTPResponse
    {
        return $this->json([
            'access_token' => $issued['access'],
            'refresh_token' => $issued['refresh'],
            'token_type' => 'Bearer',
            'expires_in' => $issued['token']->getLifetimeSeconds(),
            'scope' => $issued['token']->Scope,
        ]);
    }

    private function normaliseScope(string $requested): string
    {
        $scopes = preg_split('/[\s,]+/', trim($requested)) ?: [];

        return in_array(self::SCOPE_WRITE, $scopes, true) ? self::SCOPE_WRITE : self::SCOPE_READ;
    }

    /**
     * Loopback and custom schemes are how native clients receive the code;
     * everything else has to be https so the code is not sent in clear.
     */
    private function isAcceptableRedirectUri(string $uri): bool
    {
        $parts = parse_url($uri);

        if (!$parts || empty($parts['scheme'])) {
            return false;
        }

        $scheme = strtolower($parts['scheme']);
        $host = strtolower($parts['host'] ?? '');

        if ($scheme === 'https') {
            return true;
        }

        if ($scheme === 'http') {
            return in_array($host, ['localhost', '127.0.0.1', '[::1]', '::1'], true);
        }

        // Custom scheme, e.g. an installed application.
        return !in_array($scheme, ['javascript', 'data', 'file'], true);
    }

    private function redirectWithError(
        string $redirectUri,
        string $error,
        string $description,
        string $state
    ): HTTPResponse {
        return $this->redirect($this->appendQuery($redirectUri, array_filter([
            'error' => $error,
            'error_description' => $description,
            'state' => $state,
        ])));
    }

    /**
     * @param array<string, string> $params
     */
    private function appendQuery(string $uri, array $params): string
    {
        $separator = str_contains($uri, '?') ? '&' : '?';

        return $uri . $separator . http_build_query($params);
    }

    /**
     * Ties the consent form to this session so another site cannot submit it.
     */
    private function getSecurityToken(): string
    {
        $session = $this->getRequest()->getSession();
        $token = $session->get('SilverGateMcpConsentToken');

        if (!$token) {
            $token = bin2hex(random_bytes(16));
            $session->set('SilverGateMcpConsentToken', $token);
        }

        return $token;
    }

    /**
     * @param array<string, mixed> $data
     */
    private function json(array $data, int $statusCode = 200): HTTPResponse
    {
        $response = HTTPResponse::create(json_encode($data, JSON_UNESCAPED_SLASHES), $statusCode);
        $response->addHeader('Content-Type', 'application/json');
        $response->addHeader('Cache-Control', 'no-store');

        return $response;
    }
}
