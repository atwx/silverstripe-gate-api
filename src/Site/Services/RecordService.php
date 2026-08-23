<?php

namespace Atwx\SilverGateApi\Site\Services;

use Atwx\SilverGateApi\Exceptions\ApiException;
use SilverStripe\Core\Injector\Injectable;
use SilverStripe\Core\Validation\ValidationException;
use SilverStripe\ORM\DataList;
use SilverStripe\ORM\DataObject;
use SilverStripe\ORM\Relation;
use SilverStripe\Versioned\Versioned;

/**
 * Reads and writes records. Every operation goes through the ORM and the
 * model's own can* methods, so a token never grants more than the member it
 * acts as would have in the CMS.
 */
class RecordService
{
    use Injectable;

    public const MAX_LIMIT = 100;

    /**
     * @param array<string, mixed> $filter
     * @return array<string, mixed>
     */
    public function query(
        string $class,
        AuthContext $context,
        array $filter = [],
        ?string $sort = null,
        int $limit = 20,
        int $offset = 0,
        ?string $stage = null
    ): array {
        $limit = max(1, min($limit, self::MAX_LIMIT));
        $offset = max(0, $offset);

        $list = $this->createList($class, $stage);

        if ($filter) {
            try {
                $list = $list->filter($filter);
            } catch (\Exception $e) {
                throw new ApiException('Filter could not be applied: ' . $e->getMessage(), 400);
            }
        }

        if ($sort) {
            try {
                $list = $list->sort($sort);
            } catch (\Exception $e) {
                throw new ApiException('Sort could not be applied: ' . $e->getMessage(), 400);
            }
        }

        $total = $list->count();
        $records = [];

        foreach ($list->limit($limit, $offset) as $record) {
            if (!$record->canView($context->getMember())) {
                continue;
            }
            $records[] = $this->summarise($record);
        }

        return [
            'class' => $class,
            'total' => $total,
            'limit' => $limit,
            'offset' => $offset,
            'stage' => $stage ?: Versioned::DRAFT,
            'records' => $records,
        ];
    }

    /**
     * @return array<string, mixed>
     */
    public function get(string $class, int $id, AuthContext $context, ?string $stage = null): array
    {
        $record = $this->findOrFail($class, $id, $stage);

        if (!$record->canView($context->getMember())) {
            throw new ApiException('You may not view this record.', 403);
        }

        return $this->expand($record);
    }

    /**
     * @param array<string, mixed> $fields
     * @return array<string, mixed>
     */
    public function create(string $class, array $fields, AuthContext $context): array
    {
        $this->assertWritable($context);

        // Not DataObject::create($class) - that builds a bare DataObject and
        // passes the class name in as its record array.
        $record = $class::create();

        if (!$record->canCreate($context->getMember())) {
            throw new ApiException('You may not create records of this class.', 403);
        }

        $this->applyFields($record, $fields);
        $this->writeRecord($record);

        return $this->expand($record);
    }

    /**
     * @param array<string, mixed> $fields
     * @return array<string, mixed>
     */
    public function update(string $class, int $id, array $fields, AuthContext $context): array
    {
        $this->assertWritable($context);

        $record = $this->findOrFail($class, $id, Versioned::DRAFT);

        if (!$record->canEdit($context->getMember())) {
            throw new ApiException('You may not edit this record.', 403);
        }

        $this->applyFields($record, $fields);
        $this->writeRecord($record);

        return $this->expand($record);
    }

    /**
     * @return array<string, mixed>
     */
    public function delete(string $class, int $id, AuthContext $context): array
    {
        $this->assertWritable($context);

        $record = $this->findOrFail($class, $id, Versioned::DRAFT);

        if (!$record->canDelete($context->getMember())) {
            throw new ApiException('You may not delete this record.', 403);
        }

        $summary = $this->summarise($record);
        $this->inDraftStage(fn() => $record->delete());

        return ['deleted' => true, 'record' => $summary];
    }

    /**
     * @return array<string, mixed>
     */
    public function publish(string $class, int $id, AuthContext $context): array
    {
        $this->assertWritable($context);
        $this->assertVersioned($class);

        $record = $this->findOrFail($class, $id, Versioned::DRAFT);

        if (!$record->canPublish($context->getMember())) {
            throw new ApiException('You may not publish this record.', 403);
        }

        $this->inDraftStage(fn() => $record->publishRecursive());

        return $this->expand($record);
    }

    /**
     * @return array<string, mixed>
     */
    public function unpublish(string $class, int $id, AuthContext $context): array
    {
        $this->assertWritable($context);
        $this->assertVersioned($class);

        $record = $this->findOrFail($class, $id, Versioned::DRAFT);

        if (!$record->canUnpublish($context->getMember())) {
            throw new ApiException('You may not unpublish this record.', 403);
        }

        $this->inDraftStage(fn() => $record->doUnpublish());

        return $this->expand($record);
    }

    /**
     * Writing a field that does not exist is an error rather than a silent
     * no-op, so a caller with a typo finds out immediately.
     *
     * @param array<string, mixed> $fields
     */
    protected function applyFields(DataObject $record, array $fields): void
    {
        $deferredRelations = [];

        foreach ($fields as $name => $value) {
            if ($name === 'ID' || $name === 'ClassName') {
                throw new ApiException(sprintf('The field "%s" cannot be set through the API.', $name), 400);
            }

            if ($this->isMultiRelation($record, $name)) {
                // Relations need an ID on both sides, so they wait until after
                // the first write.
                $deferredRelations[$name] = $value;
                continue;
            }

            if (!$record->hasField($name)) {
                throw new ApiException(sprintf(
                    'Unknown field "%s" on %s.',
                    $name,
                    get_class($record)
                ), 400);
            }

            $record->setField($name, $value);
        }

        if ($deferredRelations) {
            $this->writeRecord($record);

            foreach ($deferredRelations as $name => $value) {
                $this->inDraftStage(fn() => $this->applyRelation($record, $name, $value));
            }
        }
    }

    protected function applyRelation(DataObject $record, string $name, mixed $value): void
    {
        if (!is_array($value)) {
            throw new ApiException(sprintf(
                'Relation "%s" expects an array of IDs.',
                $name
            ), 400);
        }

        $ids = [];
        foreach ($value as $item) {
            if (!is_numeric($item)) {
                throw new ApiException(sprintf(
                    'Relation "%s" expects an array of IDs, got "%s".',
                    $name,
                    is_scalar($item) ? (string) $item : gettype($item)
                ), 400);
            }
            $ids[] = (int) $item;
        }

        $relation = $this->relationList($record, $name);

        if (!$relation instanceof Relation) {
            throw new ApiException(sprintf('Relation "%s" cannot be set through the API.', $name), 400);
        }

        $relation->setByIDList($ids);
    }

    /**
     * getComponents() only covers has_many; the magic relation accessor works
     * for has_many, many_many and belongs_many_many alike.
     */
    protected function relationList(DataObject $record, string $name): ?Relation
    {
        try {
            $relation = $record->$name();
        } catch (\Exception $e) {
            return null;
        }

        return $relation instanceof Relation ? $relation : null;
    }

    protected function isMultiRelation(DataObject $record, string $name): bool
    {
        $config = $record->config();

        foreach (['has_many', 'many_many', 'belongs_many_many'] as $type) {
            if (array_key_exists($name, $config->get($type) ?: [])) {
                return true;
            }
        }

        return false;
    }

    /**
     * Writes always go to the draft stage.
     *
     * Versioned::write() targets whatever reading stage the request is in, and
     * a plain front end request reads Live. Without pinning the stage here a
     * create would publish itself.
     */
    protected function writeRecord(DataObject $record): void
    {
        try {
            Versioned::withVersionedMode(function () use ($record) {
                Versioned::set_stage(Versioned::DRAFT);
                $record->write();
            });
        } catch (ValidationException $e) {
            throw new ApiException('Validation failed: ' . $e->getMessage(), 422);
        }
    }

    /**
     * Run a callback with the reading stage pinned to draft, for the operations
     * that mutate records rather than write fields.
     */
    protected function inDraftStage(callable $callback): mixed
    {
        return Versioned::withVersionedMode(function () use ($callback) {
            Versioned::set_stage(Versioned::DRAFT);
            return $callback();
        });
    }

    protected function findOrFail(string $class, int $id, ?string $stage = null): DataObject
    {
        $record = $this->createList($class, $stage)->byID($id);

        if (!$record) {
            throw new ApiException(sprintf('No %s with ID %d.', $class, $id), 404);
        }

        return $record;
    }

    protected function createList(string $class, ?string $stage = null): DataList
    {
        if ($stage && SchemaService::singleton()->isVersioned($class)) {
            $stage = strtolower($stage) === 'live' ? Versioned::LIVE : Versioned::DRAFT;
            return Versioned::get_by_stage($class, $stage);
        }

        return DataObject::get($class);
    }

    protected function assertWritable(AuthContext $context): void
    {
        if (!$context->canWrite()) {
            throw new ApiException('This token is read only.', 403);
        }
    }

    protected function assertVersioned(string $class): void
    {
        if (!SchemaService::singleton()->isVersioned($class)) {
            throw new ApiException(sprintf('%s is not versioned, so it has nothing to publish.', $class), 400);
        }
    }

    /**
     * @return array<string, mixed>
     */
    protected function summarise(DataObject $record): array
    {
        $data = $record->toMap();
        $data['_title'] = $record->getTitle();

        if (SchemaService::singleton()->isVersioned(get_class($record))) {
            $this->inDraftStage(function () use ($record, &$data) {
                $data['_published'] = $record->isPublished();
                $data['_modified'] = $record->isModifiedOnDraft();
            });
        }

        return $data;
    }

    /**
     * Like summarise(), plus the IDs on each multi-value relation so a caller
     * can see and round trip them.
     *
     * @return array<string, mixed>
     */
    protected function expand(DataObject $record): array
    {
        $data = $this->summarise($record);
        $config = $record->config();
        $relations = [];

        foreach (['has_many', 'many_many', 'belongs_many_many'] as $type) {
            foreach (array_keys($config->get($type) ?: []) as $name) {
                $components = $this->relationList($record, $name);
                $relations[$name] = $components
                    ? array_values($components->column('ID'))
                    : [];
            }
        }

        if ($relations) {
            $data['_relations'] = $relations;
        }

        return $data;
    }
}
