<?php

namespace Atwx\SilverGateApi\Site\Services;

use SilverStripe\Core\ClassInfo;
use SilverStripe\Core\Injector\Injectable;
use SilverStripe\ORM\DataObject;
use SilverStripe\ORM\FieldType\DBEnum;
use SilverStripe\Versioned\Versioned;

/**
 * Reflects the ORM so a caller can discover what exists and what a field will
 * accept before writing to it. This is what makes the API usable without any
 * per-project knowledge.
 */
class SchemaService
{
    use Injectable;

    /**
     * @return array<int, array<string, mixed>>
     */
    public function listClasses(AuthContext $context, ?string $search = null): array
    {
        $policy = AccessPolicy::singleton();
        $result = [];

        foreach ($policy->reachableClasses($context) as $class) {
            $shortName = ClassInfo::shortName($class);

            if ($search && stripos($class, $search) === false && stripos($shortName, $search) === false) {
                continue;
            }

            $singleton = DataObject::singleton($class);

            $result[] = [
                'class' => $class,
                'shortName' => $shortName,
                'table' => DataObject::getSchema()->tableName($class),
                'singularName' => $singleton->i18n_singular_name(),
                'pluralName' => $singleton->i18n_plural_name(),
                'versioned' => $this->isVersioned($class),
            ];
        }

        return $result;
    }

    /**
     * @return array<string, mixed>
     */
    public function describe(string $class): array
    {
        $singleton = DataObject::singleton($class);
        $config = $singleton->config();

        return [
            'class' => $class,
            'shortName' => ClassInfo::shortName($class),
            'table' => DataObject::getSchema()->tableName($class),
            'singularName' => $singleton->i18n_singular_name(),
            'pluralName' => $singleton->i18n_plural_name(),
            'versioned' => $this->isVersioned($class),
            'defaultSort' => $config->get('default_sort'),
            'fields' => $this->describeFields($class, $singleton),
            'relations' => [
                'hasOne' => $this->describeHasOne($config->get('has_one') ?: []),
                'hasMany' => $this->normaliseRelation($config->get('has_many') ?: []),
                'manyMany' => $this->normaliseRelation($config->get('many_many') ?: []),
                'belongsManyMany' => $this->normaliseRelation($config->get('belongs_many_many') ?: []),
            ],
        ];
    }

    /**
     * @return array<int, array<string, mixed>>
     */
    protected function describeFields(string $class, DataObject $singleton): array
    {
        $labels = $singleton->fieldLabels(false);
        $fields = [];

        foreach (DataObject::getSchema()->fieldSpecs($class) as $name => $spec) {
            if ($name === 'ID') {
                continue;
            }

            $field = [
                'name' => $name,
                'type' => $spec,
                'label' => $labels[$name] ?? $name,
            ];

            // Enums are the field type most likely to be written wrong from the
            // outside, so surface the valid values.
            $dbObject = $singleton->dbObject($name);
            if ($dbObject instanceof DBEnum) {
                // getEnum(), not getEnumObsolete(): only values that are still
                // valid to write, not ones lingering in the database.
                $field['options'] = array_values($dbObject->getEnum());
                $field['default'] = $dbObject->getDefault();
            }

            $fields[] = $field;
        }

        return $fields;
    }

    /**
     * has_one entries may be a plain class or a ['class' => ..., 'multirelational' => ...] array.
     *
     * @param array<string, mixed> $relations
     * @return array<int, array<string, mixed>>
     */
    protected function describeHasOne(array $relations): array
    {
        $result = [];

        foreach ($relations as $name => $spec) {
            $class = is_array($spec) ? ($spec['class'] ?? null) : $spec;

            $result[] = [
                'name' => $name,
                'field' => $name . 'ID',
                'class' => $class,
            ];
        }

        return $result;
    }

    /**
     * Relation targets may carry a ".BackReference" suffix; callers only need
     * the class.
     *
     * @param array<string, string> $relations
     * @return array<int, array<string, mixed>>
     */
    protected function normaliseRelation(array $relations): array
    {
        $result = [];

        foreach ($relations as $name => $spec) {
            if (is_array($spec)) {
                // "through" relations describe themselves with an array.
                $result[] = ['name' => $name, 'class' => $spec['to'] ?? null, 'through' => true];
                continue;
            }

            $result[] = [
                'name' => $name,
                'class' => strtok((string) $spec, '.'),
                'through' => false,
            ];
        }

        return $result;
    }

    public function isVersioned(string $class): bool
    {
        return DataObject::singleton($class)->hasExtension(Versioned::class)
            && DataObject::singleton($class)->hasStages();
    }
}
