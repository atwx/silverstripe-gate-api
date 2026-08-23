<?php

namespace Atwx\SilverGateApi\Site\Controllers;

use Atwx\SilverGateApi\Exceptions\ApiException;
use Atwx\SilverGateApi\Site\Services\AccessPolicy;
use Atwx\SilverGateApi\Site\Services\AuthContext;
use Atwx\SilverGateApi\Site\Services\AuthService;
use Atwx\SilverGateApi\Site\Services\RecordService;
use Atwx\SilverGateApi\Site\Services\SchemaService;
use SilverStripe\Control\Controller;
use SilverStripe\Control\Director;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Control\HTTPResponse;
use SilverStripe\Core\Injector\Injector;

/**
 * JSON endpoint for SilverGate managed sites.
 *
 *   POST /_silvergateapi/<action>   with a JSON body
 *   GET  /_silvergateapi/ping       for a cheap reachability check
 *
 * Every request carries its own short lived JWT in the Authorization header;
 * nothing is kept in a session between calls.
 */
class ApiController extends Controller
{
    private static string $url_segment = '_silvergateapi';

    private static array $allowed_actions = [
        'index',
        'handleApiAction',
    ];

    private static array $url_handlers = [
        '' => 'index',
        '$Action' => 'handleApiAction',
    ];

    /**
     * Actions and whether they change anything. Writes are additionally gated
     * by the token scope and the model's own permission checks.
     */
    private const ACTIONS = [
        'ping' => false,
        'classes' => false,
        'schema' => false,
        'query' => false,
        'get' => false,
        'create' => true,
        'update' => true,
        'delete' => true,
        'publish' => true,
        'unpublish' => true,
    ];

    protected function init(): void
    {
        parent::init();
        $this->getResponse()->addHeader('Content-Type', 'application/json; charset=utf-8');
        // Nothing here should ever be cached or indexed.
        $this->getResponse()->addHeader('Cache-Control', 'no-store');
        $this->getResponse()->addHeader('X-Robots-Tag', 'noindex, nofollow');
    }

    public function index(HTTPRequest $request): HTTPResponse
    {
        return $this->handleApiAction($request);
    }

    public function handleApiAction(HTTPRequest $request): HTTPResponse
    {
        $action = strtolower((string) ($request->param('Action') ?: 'ping'));

        try {
            if (!array_key_exists($action, self::ACTIONS)) {
                throw new ApiException(sprintf('Unknown action "%s".', $action), 404);
            }

            if (self::ACTIONS[$action] && !$request->isPOST()) {
                throw new ApiException(sprintf('Action "%s" must be sent as POST.', $action), 405);
            }

            $context = AuthService::singleton()->authenticate($request);
            $payload = $this->readPayload($request);

            return $this->respond($this->dispatch($action, $payload, $context));
        } catch (ApiException $e) {
            return $this->respond(['error' => $e->getMessage()], $e->getStatusCode());
        } catch (\Throwable $e) {
            // Never leak internals to a caller; the site's own logger still sees it.
            Injector::inst()->get(\Psr\Log\LoggerInterface::class)->error(
                'SilverGate API failure: ' . $e->getMessage(),
                ['exception' => $e]
            );

            $error = ['error' => 'Internal error.'];

            // On a dev site the detail is worth far more than the secrecy.
            if (Director::isDev()) {
                $error['detail'] = $e->getMessage();
                $error['at'] = $e->getFile() . ':' . $e->getLine();
            }

            return $this->respond($error, 500);
        }
    }

    /**
     * @param array<string, mixed> $payload
     * @return array<string, mixed>
     */
    protected function dispatch(string $action, array $payload, AuthContext $context): array
    {
        $policy = AccessPolicy::singleton();
        $schema = SchemaService::singleton();
        $records = RecordService::singleton();

        return match ($action) {
            'ping' => [
                'ok' => true,
                'module' => 'atwx/silverstripe-gate-api',
                'member' => $context->getMember()->Email,
                'scope' => $context->getScope(),
                'classes' => $context->getClasses(),
            ],

            'classes' => [
                'classes' => $schema->listClasses($context, $this->optionalString($payload, 'search')),
            ],

            'schema' => $schema->describe(
                $policy->resolveClass($this->requireString($payload, 'class'), $context)
            ),

            'query' => $records->query(
                $policy->resolveClass($this->requireString($payload, 'class'), $context),
                $context,
                (array) ($payload['filter'] ?? []),
                $this->optionalString($payload, 'sort'),
                (int) ($payload['limit'] ?? 20),
                (int) ($payload['offset'] ?? 0),
                $this->optionalString($payload, 'stage')
            ),

            'get' => $records->get(
                $policy->resolveClass($this->requireString($payload, 'class'), $context),
                $this->requireId($payload),
                $context,
                $this->optionalString($payload, 'stage')
            ),

            'create' => $records->create(
                $policy->resolveClass($this->requireString($payload, 'class'), $context),
                $this->requireFields($payload),
                $context
            ),

            'update' => $records->update(
                $policy->resolveClass($this->requireString($payload, 'class'), $context),
                $this->requireId($payload),
                $this->requireFields($payload),
                $context
            ),

            'delete' => $records->delete(
                $policy->resolveClass($this->requireString($payload, 'class'), $context),
                $this->requireId($payload),
                $context
            ),

            'publish' => $records->publish(
                $policy->resolveClass($this->requireString($payload, 'class'), $context),
                $this->requireId($payload),
                $context
            ),

            'unpublish' => $records->unpublish(
                $policy->resolveClass($this->requireString($payload, 'class'), $context),
                $this->requireId($payload),
                $context
            ),
        };
    }

    /**
     * @return array<string, mixed>
     */
    protected function readPayload(HTTPRequest $request): array
    {
        $body = trim((string) $request->getBody());

        if ($body === '') {
            return $request->getVars();
        }

        $decoded = json_decode($body, true);

        if (!is_array($decoded)) {
            throw new ApiException('Request body must be a JSON object.', 400);
        }

        return $decoded;
    }

    /**
     * @param array<string, mixed> $data
     */
    protected function respond(array $data, int $statusCode = 200): HTTPResponse
    {
        $response = $this->getResponse();
        $response->setStatusCode($statusCode);
        $response->setBody(json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));

        return $response;
    }

    /**
     * @param array<string, mixed> $payload
     */
    protected function requireString(array $payload, string $key): string
    {
        $value = trim((string) ($payload[$key] ?? ''));

        if ($value === '') {
            throw new ApiException(sprintf('"%s" is required.', $key), 400);
        }

        return $value;
    }

    /**
     * @param array<string, mixed> $payload
     */
    protected function optionalString(array $payload, string $key): ?string
    {
        $value = trim((string) ($payload[$key] ?? ''));

        return $value === '' ? null : $value;
    }

    /**
     * @param array<string, mixed> $payload
     */
    protected function requireId(array $payload): int
    {
        $id = (int) ($payload['id'] ?? 0);

        if ($id < 1) {
            throw new ApiException('"id" is required.', 400);
        }

        return $id;
    }

    /**
     * @param array<string, mixed> $payload
     * @return array<string, mixed>
     */
    protected function requireFields(array $payload): array
    {
        $fields = $payload['fields'] ?? null;

        if (!is_array($fields) || !$fields) {
            throw new ApiException('"fields" must be a non-empty object.', 400);
        }

        return $fields;
    }
}
