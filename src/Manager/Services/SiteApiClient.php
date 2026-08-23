<?php

namespace Atwx\SilverGateApi\Manager\Services;

use Atwx\SilverGateApi\Exceptions\ApiException;
use Atwx\SilverGateManager\Models\ManagedSite;
use Atwx\SilverGateManager\Services\CryptographyService;
use GuzzleHttp\Client;
use GuzzleHttp\Exception\GuzzleException;
use SilverStripe\Core\Config\Configurable;
use SilverStripe\Core\Extensible;
use SilverStripe\Core\Injector\Injectable;

/**
 * The calling half of the API, for installs that also carry the Gate Manager.
 *
 * Signs a short lived token with the managed site's own private key and posts
 * one action to that site's /_silvergateapi endpoint. Nothing about the manager
 * module has to change for this: CryptographyService::generateJwt() already
 * accepts an arbitrary claim payload.
 */
class SiteApiClient
{
    use Configurable;
    use Injectable;
    use Extensible;

    /**
     * Request timeout in seconds.
     *
     * @config
     */
    private static int $timeout = 15;

    /**
     * Scheme used to reach managed sites.
     *
     * @config
     */
    private static string $scheme = 'https';

    private ?Client $httpClient = null;

    public function setHttpClient(Client $client): static
    {
        $this->httpClient = $client;
        return $this;
    }

    /**
     * Call one action on a managed site.
     *
     * @param array<string, mixed> $payload Action arguments.
     * @param array<string, mixed> $claims  Extra token claims: sub, scope, classes.
     * @return array<string, mixed>
     */
    public function call(ManagedSite $site, string $action, array $payload = [], array $claims = []): array
    {
        if (!$site->isInDB() || !$site->Domain) {
            throw new ApiException('The managed site has no domain.', 400);
        }

        $response = $this->send($site, $action, $payload, $claims);
        $decoded = json_decode($response, true);

        if (!is_array($decoded)) {
            throw new ApiException(sprintf(
                'Site %s did not return JSON. It may not have the gate API installed.',
                $site->Domain
            ), 502);
        }

        if (isset($decoded['error'])) {
            throw new ApiException(sprintf('%s: %s', $site->Domain, $decoded['error']), 502);
        }

        return $decoded;
    }

    /**
     * Convenience wrappers so callers do not have to remember action names.
     *
     * @return array<string, mixed>
     */
    public function ping(ManagedSite $site, array $claims = []): array
    {
        return $this->call($site, 'ping', [], $claims);
    }

    /**
     * @return array<string, mixed>
     */
    public function schema(ManagedSite $site, string $class, array $claims = []): array
    {
        return $this->call($site, 'schema', ['class' => $class], $claims);
    }

    /**
     * @param array<string, mixed> $payload
     * @return array<string, mixed>
     */
    public function query(ManagedSite $site, string $class, array $payload = [], array $claims = []): array
    {
        return $this->call($site, 'query', array_merge(['class' => $class], $payload), $claims);
    }

    /**
     * @param array<string, mixed> $fields
     * @return array<string, mixed>
     */
    public function create(ManagedSite $site, string $class, array $fields, array $claims = []): array
    {
        return $this->call(
            $site,
            'create',
            ['class' => $class, 'fields' => $fields],
            $this->withWriteScope($claims)
        );
    }

    /**
     * @param array<string, mixed> $fields
     * @return array<string, mixed>
     */
    public function update(ManagedSite $site, string $class, int $id, array $fields, array $claims = []): array
    {
        return $this->call(
            $site,
            'update',
            ['class' => $class, 'id' => $id, 'fields' => $fields],
            $this->withWriteScope($claims)
        );
    }

    public function getEndpoint(ManagedSite $site, string $action): string
    {
        return sprintf(
            '%s://%s/_silvergateapi/%s',
            $this->config()->get('scheme'),
            $site->Domain,
            ltrim($action, '/')
        );
    }

    /**
     * @param array<string, mixed> $claims
     * @return array<string, mixed>
     */
    protected function withWriteScope(array $claims): array
    {
        return array_merge(['scope' => 'write'], $claims);
    }

    /**
     * @param array<string, mixed> $payload
     * @param array<string, mixed> $claims
     */
    protected function send(ManagedSite $site, string $action, array $payload, array $claims): string
    {
        $token = $this->generateToken($site, $claims);

        try {
            $response = $this->getHttpClient()->post($this->getEndpoint($site, $action), [
                'headers' => [
                    'Authorization' => 'Bearer ' . $token,
                    'Content-Type' => 'application/json',
                    'Accept' => 'application/json',
                ],
                'body' => json_encode($payload),
                'timeout' => $this->config()->get('timeout'),
                'http_errors' => false,
            ]);
        } catch (GuzzleException $e) {
            throw new ApiException(sprintf('Could not reach %s: %s', $site->Domain, $e->getMessage()), 502);
        }

        return (string) $response->getBody();
    }

    /**
     * @param array<string, mixed> $claims
     */
    protected function generateToken(ManagedSite $site, array $claims): string
    {
        $this->extend('updateApiClaims', $claims, $site);

        return CryptographyService::singleton()->generateJwt(
            privateKey: $site->PrivateKey,
            payload: $claims,
            issuedAt: time()
        );
    }

    protected function getHttpClient(): Client
    {
        return $this->httpClient ??= new Client();
    }
}
