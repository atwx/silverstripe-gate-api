<?php

namespace Atwx\SilverGateApi\Site\Services;

use Atwx\SilverGateApi\Exceptions\ApiException;
use SilverStripe\Core\ClassInfo;
use SilverStripe\Core\Config\Configurable;
use SilverStripe\Core\Extensible;
use SilverStripe\Core\Injector\Injectable;
use SilverStripe\ORM\DataObject;

/**
 * Decides which DataObject classes the API will touch at all.
 *
 * Three gates, narrowest wins:
 *   1. denied_classes  - never reachable, whatever the token says
 *   2. allowed_classes - if set, nothing outside the list is reachable
 *   3. the token's own "classes" claim
 *
 * This runs before any canView()/canEdit() check. Those still apply; this only
 * keeps whole classes out of reach so a leaked token cannot be pointed at, say,
 * the security tables.
 */
class AccessPolicy
{
    use Configurable;
    use Injectable;
    use Extensible;

    /**
     * Classes that are never reachable. Subclasses are covered too.
     *
     * @config
     */
    private static array $denied_classes = [];

    /**
     * If non-empty, only these classes (and their subclasses) are reachable.
     *
     * @config
     */
    private static array $allowed_classes = [];

    /**
     * Resolve a short name or FQCN to a DataObject class, checking it is
     * reachable for this request.
     */
    public function resolveClass(string $name, AuthContext $context): string
    {
        $class = $this->findClass($name);

        if (!$class) {
            throw new ApiException(sprintf('Unknown DataObject class "%s".', $name), 404);
        }

        if (!$this->isReachable($class, $context)) {
            // Deliberately the same message as an unknown class: a caller that
            // is not allowed to see a class should not learn it exists.
            throw new ApiException(sprintf('Unknown DataObject class "%s".', $name), 404);
        }

        return $class;
    }

    public function isReachable(string $class, ?AuthContext $context = null): bool
    {
        if (!is_a($class, DataObject::class, true) || $class === DataObject::class) {
            return false;
        }

        foreach ($this->config()->get('denied_classes') as $denied) {
            if (is_a($class, $denied, true)) {
                return false;
            }
        }

        $allowed = $this->config()->get('allowed_classes');
        if ($allowed && !$this->matchesAny($class, $allowed)) {
            return false;
        }

        $claimed = $context?->getClasses();
        if ($claimed && !$this->matchesAny($class, $claimed)) {
            return false;
        }

        return true;
    }

    /**
     * Every reachable class, for the classes listing.
     *
     * @return string[]
     */
    public function reachableClasses(?AuthContext $context = null): array
    {
        $classes = array_filter(
            ClassInfo::subclassesFor(DataObject::class, false),
            fn(string $class) => $this->isReachable($class, $context)
        );

        sort($classes);

        return array_values($classes);
    }

    /**
     * Accepts a fully qualified name, or a short name when it is unambiguous.
     */
    protected function findClass(string $name): ?string
    {
        $name = trim($name);

        if ($name === '') {
            return null;
        }

        if (class_exists($name) && is_a($name, DataObject::class, true)) {
            return $name;
        }

        $matches = [];
        foreach (ClassInfo::subclassesFor(DataObject::class, false) as $class) {
            if (strcasecmp(ClassInfo::shortName($class), $name) === 0) {
                $matches[] = $class;
            }
        }

        if (count($matches) > 1) {
            throw new ApiException(sprintf(
                'The short name "%s" is ambiguous: %s. Use the fully qualified name.',
                $name,
                implode(', ', $matches)
            ), 400);
        }

        return $matches[0] ?? null;
    }

    /**
     * @param string[] $candidates
     */
    protected function matchesAny(string $class, array $candidates): bool
    {
        foreach ($candidates as $candidate) {
            $candidate = trim((string) $candidate);

            if ($candidate === '') {
                continue;
            }

            if (is_a($class, $candidate, true)) {
                return true;
            }

            // Allow short names in the config and in token claims.
            if (strcasecmp(ClassInfo::shortName($class), $candidate) === 0) {
                return true;
            }
        }

        return false;
    }
}
