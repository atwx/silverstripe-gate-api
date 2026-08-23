<?php

namespace Atwx\SilverGateApi\Manager\Controllers;

use Atwx\SilverGateApi\Exceptions\ApiException;
use Atwx\SilverGateApi\Manager\Mcp\ToolRegistry;
use Atwx\SilverGateApi\Manager\OAuth\OAuthToken;
use SilverStripe\Control\Controller;
use SilverStripe\Control\Director;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Control\HTTPResponse;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\Security\Security;
use Throwable;

/**
 * Model Context Protocol endpoint: JSON-RPC 2.0 over HTTP POST.
 *
 * One server for every managed site. Tools take a "site" argument rather than
 * the server being installed per site, so a client sees one small tool set
 * instead of one set per site.
 *
 * Authentication is a bearer token from OAuthController. The token names a
 * member, and every call acts as that member all the way down to the target
 * site's canEdit().
 */
class McpController extends Controller
{
    private static string $url_segment = '_silvergatemcp';

    private static array $allowed_actions = [
        'index',
    ];

    private const PROTOCOL_VERSION = '2024-11-05';

    protected function init(): void
    {
        Controller::init();
    }

    public function index(HTTPRequest $request): HTTPResponse
    {
        if (!$request->isPOST()) {
            return $this->challenge('This endpoint speaks JSON-RPC over POST.', 405);
        }

        $token = $this->authenticate($request);

        if (!$token) {
            return $this->challenge('A valid bearer token is required.', 401);
        }

        $payload = json_decode((string) $request->getBody(), true);

        if (!is_array($payload)) {
            return $this->rpcError(null, -32700, 'Parse error');
        }

        // A batch is a plain list of calls; a single call is an object.
        if (array_is_list($payload)) {
            $responses = array_values(array_filter(array_map(
                fn(array $call) => $this->handleCall($call, $token),
                $payload
            )));

            return $responses ? $this->json($responses) : $this->noContent();
        }

        $response = $this->handleCall($payload, $token);

        return $response ? $this->json($response) : $this->noContent();
    }

    /**
     * @param array<string, mixed> $call
     * @return array<string, mixed>|null Null for notifications, which get no reply.
     */
    private function handleCall(array $call, OAuthToken $token): ?array
    {
        $id = $call['id'] ?? null;
        $method = (string) ($call['method'] ?? '');
        $params = (array) ($call['params'] ?? []);

        // Notifications carry no id and must not be answered.
        if ($id === null) {
            return null;
        }

        try {
            return $this->rpcResult($id, match ($method) {
                'initialize' => $this->initialize(),
                'ping' => (object) [],
                'tools/list' => ['tools' => $this->registry()->listTools($token->Member(), $this->mayWrite($token))],
                'tools/call' => $this->callTool($params, $token),
                default => throw new ApiException(sprintf('Unknown method "%s".', $method), 404),
            });
        } catch (ApiException $e) {
            return $this->rpcError($id, -32000, $e->getMessage());
        } catch (Throwable $e) {
            Injector::inst()->get(\Psr\Log\LoggerInterface::class)->error(
                'SilverGate MCP failure: ' . $e->getMessage(),
                ['exception' => $e]
            );

            $message = Director::isDev() ? $e->getMessage() : 'Internal error.';

            return $this->rpcError($id, -32603, $message);
        }
    }

    /**
     * @return array<string, mixed>
     */
    private function initialize(): array
    {
        return [
            'protocolVersion' => self::PROTOCOL_VERSION,
            'capabilities' => ['tools' => (object) []],
            'serverInfo' => [
                'name' => 'silverstripe-gate-api',
                'version' => '1.0',
            ],
            'instructions' => 'Content access to the Silverstripe sites managed here. '
                . 'Call sites_list first, then site_schema before writing, so field types '
                . 'and valid Enum values are known. Writes on versioned records go to draft '
                . 'until site_publish is called.',
        ];
    }

    /**
     * @param array<string, mixed> $params
     * @return array<string, mixed>
     */
    private function callTool(array $params, OAuthToken $token): array
    {
        $name = (string) ($params['name'] ?? '');
        $arguments = (array) ($params['arguments'] ?? []);

        try {
            $result = $this->registry()->call($name, $arguments, $token->Member(), $this->mayWrite($token));
        } catch (ApiException $e) {
            // Tool failures are reported in the result rather than as protocol
            // errors, so the model can read them and adjust.
            return [
                'content' => [['type' => 'text', 'text' => $e->getMessage()]],
                'isError' => true,
            ];
        }

        return [
            'content' => [[
                'type' => 'text',
                'text' => json_encode($result, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE),
            ]],
        ];
    }

    private function authenticate(HTTPRequest $request): ?OAuthToken
    {
        $header = (string) $request->getHeader('authorization');

        if (!preg_match('/^Bearer\s+(.+)$/i', trim($header), $matches)) {
            return null;
        }

        $token = OAuthToken::findByAccessToken(trim($matches[1]));

        if (!$token) {
            return null;
        }

        $member = $token->Member();

        if (!$member || !$member->exists()) {
            return null;
        }

        $token->touch();
        Security::setCurrentUser($member);

        return $token;
    }

    private function mayWrite(OAuthToken $token): bool
    {
        return $token->Scope === OAuthController::SCOPE_WRITE;
    }

    private function registry(): ToolRegistry
    {
        return ToolRegistry::singleton();
    }

    /**
     * @return array<string, mixed>
     */
    private function rpcResult(mixed $id, mixed $result): array
    {
        return ['jsonrpc' => '2.0', 'id' => $id, 'result' => $result];
    }

    /**
     * @return array<string, mixed>
     */
    private function rpcErrorBody(mixed $id, int $code, string $message): array
    {
        return ['jsonrpc' => '2.0', 'id' => $id, 'error' => ['code' => $code, 'message' => $message]];
    }

    private function rpcError(mixed $id, int $code, string $message): array|HTTPResponse
    {
        $body = $this->rpcErrorBody($id, $code, $message);

        return $id === null ? $this->json($body) : $body;
    }

    /**
     * Points an unauthenticated client at the metadata it needs, per RFC 9728.
     */
    private function challenge(string $message, int $statusCode): HTTPResponse
    {
        $response = $this->json($this->rpcErrorBody(null, -32001, $message), $statusCode);

        if ($statusCode === 401) {
            $response->addHeader('WWW-Authenticate', sprintf(
                'Bearer resource_metadata="%s/.well-known/oauth-protected-resource"',
                rtrim(Director::absoluteBaseURL(), '/')
            ));
        }

        return $response;
    }

    private function noContent(): HTTPResponse
    {
        return HTTPResponse::create('', 202);
    }

    private function json(array $data, int $statusCode = 200): HTTPResponse
    {
        $response = HTTPResponse::create(
            json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE),
            $statusCode
        );
        $response->addHeader('Content-Type', 'application/json');
        $response->addHeader('Cache-Control', 'no-store');

        return $response;
    }
}
