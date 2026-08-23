<?php

namespace Atwx\SilverGateApi\Exceptions;

use RuntimeException;

/**
 * Carries an HTTP status code so the controller can turn any failure deeper in
 * the stack into a proper JSON error response.
 */
class ApiException extends RuntimeException
{
    private int $statusCode;

    public function __construct(string $message, int $statusCode = 400)
    {
        parent::__construct($message);
        $this->statusCode = $statusCode;
    }

    public function getStatusCode(): int
    {
        return $this->statusCode;
    }
}
