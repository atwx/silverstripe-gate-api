<?php

namespace Atwx\SilverGateApi\Site\Services;

use Atwx\SilverGateApi\Exceptions\ApiException;
use Atwx\SilverGateClient\Services\LoginService;
use Atwx\SilverGateClient\Services\TokenService;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Core\Config\Config;
use SilverStripe\Core\Config\Configurable;
use SilverStripe\Core\Environment;
use SilverStripe\Core\Extensible;
use SilverStripe\Core\Injector\Injectable;
use SilverStripe\Security\Member;
use SilverStripe\Security\Security;
use stdClass;

/**
 * Turns the SilverGate JWT on a request into an AuthContext.
 *
 * Signature and age are validated by the gate client's TokenService so both
 * modules agree on what a valid token is. The payload is decoded a second time
 * here because TokenService only reports a boolean and discards the claims.
 *
 * Supported claims, all optional:
 *
 *   sub      Email or ID of the member to act as. A subject that names
 *            nobody here falls back to the gate client's configured member,
 *            exactly as an absent claim does.
 *   scope    "read" (default) or "write".
 *   classes  Array of class names the token is limited to.
 *
 * Unlike the gate client's browser login this never starts a session. The
 * member is set for the duration of the request only, so every call has to
 * carry its own token.
 */
class AuthService
{
    use Configurable;
    use Injectable;
    use Extensible;

    /**
     * Set to false to make the site reject every write, no matter what the
     * token claims.
     *
     * @config
     */
    private static bool $allow_writes = true;

    public function authenticate(HTTPRequest $request): AuthContext
    {
        $jwt = $this->extractToken($request);

        if (!TokenService::singleton()->validateJwt($jwt)) {
            throw new ApiException('Token is invalid or expired.', 403);
        }

        $claims = $this->decodeClaims($jwt);
        $member = $this->resolveMember($claims);

        if (!$member) {
            throw new ApiException('No valid member to act as was found.', 403);
        }

        $scope = $this->resolveScope($claims);
        $classes = $this->resolveClasses($claims);

        // Make the member current for this request so canView()/canEdit() apply,
        // without persisting anything to a session.
        Security::setCurrentUser($member);

        return new AuthContext($member, $scope, $classes);
    }

    protected function extractToken(HTTPRequest $request): string
    {
        $header = (string) $request->getHeader('authorization');

        if (!preg_match('/^Bearer\s+(.+)$/i', trim($header), $matches)) {
            throw new ApiException('Missing or malformed Authorization header.', 401);
        }

        $token = trim($matches[1]);

        // Accept both the raw JWT and the base64 form the gate client's login
        // endpoint uses, so callers can reuse the same encoding.
        if (substr_count($token, '.') !== 2) {
            $decoded = base64_decode(urldecode($token), true);
            if ($decoded && substr_count($decoded, '.') === 2) {
                $token = $decoded;
            }
        }

        if (substr_count($token, '.') !== 2) {
            throw new ApiException('Token format is invalid.', 401);
        }

        return $token;
    }

    protected function decodeClaims(string $jwt): stdClass
    {
        $algorithm = $this->getJwtAlgorithm($jwt);

        if (!$algorithm) {
            throw new ApiException('Unsupported token algorithm.', 403);
        }

        try {
            return JWT::decode($jwt, new Key($this->getPublicKey(), $algorithm));
        } catch (\Exception $e) {
            // TokenService already accepted the token, so getting here means the
            // two modules disagree about the key. Do not leak the detail.
            throw new ApiException('Token could not be read.', 403);
        }
    }

    protected function resolveMember(stdClass $claims): ?Member
    {
        $subject = isset($claims->sub) ? trim((string) $claims->sub) : '';

        if ($subject !== '') {
            $member = ctype_digit($subject)
                ? Member::get()->byID((int) $subject)
                : Member::get()->filter('Email', $subject)->first();

            if ($member) {
                return $member;
            }

            // The token is signed with this site's key, so the caller is
            // trusted and only the member it names is unknown here. Managers
            // address many sites and cannot have an account on each, so fall
            // through to the default rather than refusing the call.
        }

        return LoginService::singleton()->findMember();
    }

    protected function resolveScope(stdClass $claims): string
    {
        $scope = isset($claims->scope) ? strtolower(trim((string) $claims->scope)) : AuthContext::SCOPE_READ;

        if ($scope === AuthContext::SCOPE_WRITE && !$this->config()->get('allow_writes')) {
            throw new ApiException('This site does not accept writes through the API.', 403);
        }

        if (!in_array($scope, [AuthContext::SCOPE_READ, AuthContext::SCOPE_WRITE], true)) {
            throw new ApiException(sprintf('Unknown scope "%s".', $scope), 403);
        }

        return $scope;
    }

    /**
     * @return string[]|null
     */
    protected function resolveClasses(stdClass $claims): ?array
    {
        if (!isset($claims->classes)) {
            return null;
        }

        $classes = array_values(array_filter(array_map(
            fn($class) => trim((string) $class),
            (array) $claims->classes
        )));

        // An empty list is a token that may touch nothing, which is almost
        // certainly a mistake on the issuing side.
        if (!$classes) {
            throw new ApiException('The token allows no classes at all.', 403);
        }

        return $classes;
    }

    /**
     * Mirrors the gate client so both modules read the key from the same place.
     */
    protected function getPublicKey(): string
    {
        $key = Environment::getEnv('SILVERGATECLIENT_PUBLIC_KEY')
            ?: Config::inst()->get(TokenService::class, 'public_key');

        if (!$key) {
            throw new ApiException('No SilverGate public key is configured on this site.', 500);
        }

        // Keys supplied through .env carry escaped newlines.
        return str_replace('\n', "\n", (string) $key);
    }

    protected function getJwtAlgorithm(string $jwt): ?string
    {
        $parts = explode('.', $jwt);

        if (count($parts) !== 3) {
            return null;
        }

        $header = JWT::jsonDecode(JWT::urlsafeB64Decode($parts[0]));
        $algorithm = $header->alg ?? null;

        return $algorithm && array_key_exists($algorithm, JWT::$supported_algs) ? $algorithm : null;
    }
}
