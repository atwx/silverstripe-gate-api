<?php

namespace Atwx\SilverGateApi\Tests;

use Atwx\SilverGateApi\Manager\Controllers\OAuthController;
use PHPUnit\Framework\Attributes\DataProvider;
use SilverStripe\Control\Director;
use SilverStripe\Core\Config\Config;
use SilverStripe\Dev\SapphireTest;

/**
 * Director::absoluteBaseURL() ends in a slash on some installs and not on
 * others. Concatenating a path onto it therefore works locally and produces
 * "example.com_silvergatemcp" in production, which is exactly what happened.
 * These run both ways.
 */
class EndpointUrlTest extends SapphireTest
{
    protected $usesDatabase = false;

    public static function baseUrls(): array
    {
        return [
            'with trailing slash' => ['https://example.com/'],
            'without trailing slash' => ['https://example.com'],
            'in a subdirectory' => ['https://example.com/intranet/'],
        ];
    }

    private function withBase(string $base): void
    {
        Config::modify()->set(Director::class, 'alternate_base_url', $base);
    }

    #[DataProvider('baseUrls')]
    public function testEndpointsAreWellFormed(string $base): void
    {
        $this->withBase($base);

        $url = OAuthController::endpoint('_silvergatemcp/oauth/approve');

        $this->assertStringStartsWith('https://example.com/', $url);
        $this->assertStringEndsWith('/_silvergatemcp/oauth/approve', $url);
        $this->assertStringNotContainsString('com_silvergatemcp', $url);
        $this->assertStringNotContainsString('//_silvergatemcp', $url);
    }

    #[DataProvider('baseUrls')]
    public function testMetadataUrlsAreWellFormed(string $base): void
    {
        $this->withBase($base);

        $metadata = OAuthController::metadata();

        foreach (['authorization_endpoint', 'token_endpoint', 'registration_endpoint'] as $key) {
            $url = $metadata[$key];

            $this->assertNotFalse(
                filter_var($url, FILTER_VALIDATE_URL),
                sprintf('%s is not a valid URL: %s', $key, $url)
            );
            $this->assertStringContainsString('/_silvergatemcp/oauth/', $url);
            $this->assertStringNotContainsString('com_silvergatemcp', $url);
        }
    }

    #[DataProvider('baseUrls')]
    public function testIssuerHasNoTrailingSlash(string $base): void
    {
        $this->withBase($base);

        $this->assertStringEndsNotWith('/', OAuthController::issuer());
    }
}
