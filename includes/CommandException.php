<?php
declare(strict_types = 1);

namespace Mireiawen\CSR;

/**
 * Exception for command errors
 *
 * @package Mireiawen\CSR
 */
class CommandException extends \RuntimeException
{
	/**
	 * Constructor that sets the message
	 *
	 * @param string $message
	 *    The error message
	 *
	 * @param int $code
	 *    The code
	 *
	 * @param \Throwable|NULL $previous
	 *    Previous exception
	 */
	public function __construct(string $message = '', int $code = 0, \Throwable $previous = NULL)
	{
		parent::__construct(\sprintf(\_('Command error: %s'), $message), $code, $previous);
	}
	
}