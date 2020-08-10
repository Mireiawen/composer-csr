<?php
declare(strict_types = 1);

namespace Mireiawen\CSR;

/**
 * Exception for OpenSSL errors
 *
 * @package Mireiawen\CSR
 */
class OpenSSLException extends \RuntimeException
{
	/**
	 * Constructor that sets the message
	 *
	 * @param string $message
	 *    The uninitialized variable
	 *
	 * @param int $code
	 *    The code
	 *
	 * @param \Throwable|NULL $previous
	 *    Previous exception
	 */
	public function __construct(string $message = '', int $code = 0, \Throwable $previous = NULL)
	{
		parent::__construct(\sprintf(\_('OpenSSL error %s: %s'), $message, \openssl_error_string()), $code, $previous);
	}
}