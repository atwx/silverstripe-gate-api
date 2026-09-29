<?php

namespace Atwx\SilverGateApi\Site\Services;

use Atwx\SilverGateApi\Exceptions\ApiException;
use SilverStripe\Assets\File;
use SilverStripe\Assets\Folder;
use SilverStripe\Assets\Upload;
use SilverStripe\Control\Director;
use SilverStripe\Core\Config\Configurable;
use SilverStripe\Core\Injector\Injectable;
use SilverStripe\Versioned\Versioned;

/**
 * Stores uploaded files as File records.
 *
 * Goes through Silverstripe's own Upload handler, so the site's allowed
 * extensions, size limits and file name filter apply exactly as they would for
 * an upload in the CMS.
 */
class FileService
{
    use Configurable;
    use Injectable;

    /**
     * Folder used when the caller names none.
     *
     * @config
     */
    private static string $default_folder = 'Uploads';

    /**
     * @param array<string, mixed> $tmpFile A PHP upload array.
     * @return array<string, mixed>
     */
    public function upload(
        array $tmpFile,
        AuthContext $context,
        ?string $folder = null,
        ?string $filename = null,
        ?string $title = null,
        bool $publish = true
    ): array {
        if (!$context->canWrite()) {
            throw new ApiException('This token is read only.', 403);
        }

        // Respects allowed_classes, denied_classes and the token's classes claim.
        AccessPolicy::singleton()->resolveClass(File::class, $context);

        $member = $context->getMember();

        if (!File::singleton()->canCreate($member)) {
            throw new ApiException('You may not upload files.', 403);
        }

        if ((int) $tmpFile['error'] !== UPLOAD_ERR_OK) {
            throw new ApiException($this->describeUploadError((int) $tmpFile['error']), 400);
        }

        if ($filename !== null) {
            $tmpFile['name'] = $filename;
        }

        $folderPath = $this->normaliseFolder($folder);

        return $this->inDraftStage(function () use ($tmpFile, $folderPath, $title, $publish, $member) {
            $parent = Folder::find_or_make($folderPath);

            if (!$parent->canEdit($member)) {
                throw new ApiException(sprintf('You may not upload into "%s".', $folderPath), 403);
            }

            $upload = Upload::create();

            if (!$upload->loadIntoFile($tmpFile, null, $folderPath)) {
                throw new ApiException('Upload rejected: ' . implode(' ', $upload->getErrors()), 422);
            }

            /** @var File $file */
            $file = $upload->getFile();

            if ($title !== null) {
                $file->Title = $title;
                $file->write();
            }

            if ($publish) {
                if (!$file->canPublish($member)) {
                    throw new ApiException('The file was stored, but you may not publish it.', 403);
                }
                $file->publishSingle();
            }

            return $this->describe($file);
        });
    }

    /**
     * @return array<string, mixed>
     */
    public function describe(File $file): array
    {
        return [
            'ClassName' => get_class($file),
            'ID' => $file->ID,
            'Title' => $file->Title,
            'Name' => $file->Name,
            'Filename' => $file->getFilename(),
            'ParentID' => $file->ParentID,
            'Size' => $file->getAbsoluteSize(),
            'URL' => $file->getURL(),
            'AbsoluteURL' => Director::absoluteURL((string) $file->getURL()),
            '_title' => $file->getTitle(),
            '_published' => $file->isPublished(),
            '_modified' => $file->isModifiedOnDraft(),
        ];
    }

    protected function normaliseFolder(?string $folder): string
    {
        $folder = trim((string) $folder, " /");

        if ($folder === '') {
            return $this->config()->get('default_folder');
        }

        if (preg_match('#(^|/)\.\.?(/|$)#', $folder)) {
            throw new ApiException('The folder must not contain "." or ".." segments.', 400);
        }

        return $folder;
    }

    protected function describeUploadError(int $error): string
    {
        return match ($error) {
            UPLOAD_ERR_INI_SIZE, UPLOAD_ERR_FORM_SIZE => sprintf(
                'The file is larger than the site accepts (upload_max_filesize %s, post_max_size %s).',
                ini_get('upload_max_filesize'),
                ini_get('post_max_size')
            ),
            UPLOAD_ERR_PARTIAL => 'The file arrived only partially.',
            UPLOAD_ERR_NO_FILE => 'No file was sent.',
            default => sprintf('The upload failed with PHP error %d.', $error),
        };
    }

    /**
     * Uploads always land in draft first, as with every other write.
     */
    protected function inDraftStage(callable $callback): mixed
    {
        return Versioned::withVersionedMode(function () use ($callback) {
            Versioned::set_stage(Versioned::DRAFT);
            return $callback();
        });
    }
}
