<?php
declare(strict_types = 1);

namespace Mireiawen\CSR;

/**
 * Helper class to parse Certificate Signing Requests
 *
 * @package Mireiawen\CSR
 */
class CSR
{
	/**
	 * @param string $csr
	 *    The certificate request to parse
	 *
	 * @return array
	 *    The fields parsed
	 *
	 * @throws \InvalidArgumentException
	 *    In case the certificate request does not contain the BEGIN line
	 *
	 * @throws FileSystemException
	 *    In case of unable to use temporary file
	 *
	 * @throws CommandException
	 *    In case of unable to execute openssl command
	 */
	public static function Parse(string $csr) : array
	{
		if (\strpos($csr, 'BEGIN CERTIFICATE REQUEST') === FALSE)
		{
			throw new \InvalidArgumentException(\_('Unable to detect BEGIN CERTIFICATE REQUEST'));
		}
		
		// Read the subject
		$subject = \openssl_csr_get_subject($csr);
		if ($subject === FALSE)
		{
			throw new OpenSSLException(\_('when reading subject'));
		}
		
		// Read the public key
		$public_key = \openssl_csr_get_public_key($csr);
		if ($public_key === FALSE)
		{
			throw new OpenSSLException(\_('when reading public key'));
		}
		
		// Read the public key details
		$details = \openssl_pkey_get_details($public_key);
		if ($details === FALSE)
		{
			throw new OpenSSLException(\_('when reading public key details'));
		}
		
		// Create the parse result array
		return
			[
				'subject' => $subject,
				'key' => $details['key'],
				'bits' => $details['bits'],
				'pem' => $csr,
				'sans' => self::GetSANS($csr),
			];
	}
	
	/**
	 * Get the SAN fields from CSR text
	 *
	 * @param string $csr
	 *    The CSR text to read
	 *
	 * @return string[]
	 *    The array of Subject Alternative Names
	 *
	 * @throws FileSystemException
	 *    In case of unable to use temporary file
	 *
	 * @throws CommandException
	 *    In case of unable to execute openssl command
	 */
	public static function GetSANS(string $csr) : array
	{
		// Write the CSR to a temporary file
		$temp_csr = \tempnam(\sys_get_temp_dir(), 'csr');
		if ($temp_csr === FALSE)
		{
			throw new FileSystemException(\sprintf(\_('Unable to create a temporary file %s'), $temp_csr));
		}
		
		if (\file_put_contents($temp_csr, $csr) === FALSE)
		{
			\unlink($temp_csr);
			throw new FileSystemException(\sprintf(\_('Unable to write to the temporary file'), $temp_csr));
		}
		
		// Parse the SANs with OpenSSL from the temporary file
		/** @noinspection SpellCheckingInspection */
		$openssl = \sprintf('bash -c \'timeout %d openssl req -noout -text -in "%s" |grep -e \'DNS:\' -e \'IP:\'; exit "${PIPESTATUS[0]}"\'', 30, $temp_csr);
		\exec($openssl, $output, $code);
		\unlink($temp_csr);
		
		// Error case
		if ($code !== 0)
		{
			throw new CommandException(\_('Running the OpenSSL command to read the CSR failed'));
		}
		
		// Glue the output to single string
		$output = \trim(\implode("\n", $output));
		
		// Make sure some defaults are always set in the array
		$sans = [
			'DNS' => [],
			'IP Address' => [],
			'email' => [],
		];
		
		// Do the actual parsing
		foreach (self::ParseSAN($output) as $item => $value)
		{
			$sans[$item][] = $value;
		}
		
		return $sans;
	}
	
	/**
	 * Parse the SAN fields from the OpenSSL output
	 *
	 * @param string $data
	 *    The output data
	 *
	 * @return \Generator
	 */
	protected static function ParseSAN(string $data) : \Generator
	{
		$sans = \explode(',', $data);
		
		// Go through the SANs
		foreach ($sans as $san)
		{
			// Empty string, ignore
			if (empty($san))
			{
				continue;
			}
			
			// String without the expected key:value -pair, ignore
			if (\strpos($san, ':') === FALSE)
			{
				continue;
			}
			
			[$key, $value] = \explode(':', $san, 2);
			
			$key = \trim($key);
			$value = \trim($value);
			
			if (empty($key) || empty($value))
			{
				continue;
			}
			
			yield $key => $value;
		}
	}
}