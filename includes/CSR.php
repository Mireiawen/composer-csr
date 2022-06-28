<?php
declare(strict_types = 1);

namespace Mireiawen\CSR;

use JetBrains\PhpStorm\ArrayShape;

/**
 * Helper class to parse Certificate Signing Requests
 *
 * @package Mireiawen\CSR
 */
class CSR
{
	/**
	 * The OpenSSL certificate subject array
	 *
	 * @var array
	 */
	protected array $subject;
	
	/**
	 * The OpenSSL certificate key type
	 *
	 * @var int
	 */
	protected int $key;
	
	/**
	 * The OpenSSL certificate key bits
	 *
	 * @var int
	 */
	protected int $bits;
	
	/**
	 * The OpenSSL certificate signing request in PEM format
	 *
	 * @var string
	 */
	protected string $pem;
	
	/**
	 * The SANs (Subject Alternative Names) extracted from the request
	 *
	 * @var array
	 */
	#[ArrayShape(['DNS' => "array", 'IP Address' => "array", 'email' => "array"])]
	protected array $sans;
	
	/**
	 * @param string $csr
	 *    The certificate request to parse
	 *
	 * @return self
	 *    The CSR object
	 *
	 * @throws \InvalidArgumentException
	 *    In case the certificate request does not contain the "begin certificate request" -line
	 *
	 * @throws FileSystemException
	 *    In case of unable to use temporary file
	 *
	 * @throws CommandException
	 *    In case of unable to execute openssl command
	 */
	public static function Parse(string $csr) : self
	{
		if (!str_contains($csr, 'BEGIN CERTIFICATE REQUEST'))
		{
			throw new \InvalidArgumentException(\_('Unable to detect BEGIN CERTIFICATE REQUEST'));
		}
		
		// Read the subject
		$subject = \openssl_csr_get_subject($csr, TRUE);
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
		
		// Create the resulting object
		return new self($subject, $details['type'], $details['bits'], $csr);
	}
	
	/**
	 * Create instance of the CSR object
	 *
	 * @param array $subject
	 * @param int $key
	 * @param int $bits
	 * @param string $csr
	 */
	protected function __construct(array $subject, int $key, int $bits, string $csr)
	{
		$this->subject = $subject;
		$this->key = $key;
		$this->bits = $bits;
		$this->pem = $csr;
		$this->ReadSANs();
	}
	
	/**
	 * Get the OpenSSL certificate subject array
	 *
	 * @return array
	 */
	public function GetSubject() : array
	{
		return $this->subject;
	}
	
	/**
	 * Get the country from the subject
	 *
	 * @return string
	 */
	public function GetCountry() : string
	{
		return $this->subject['C'] ?? '';
	}
	
	/**
	 * Get the locality from the subject
	 *
	 * @return string
	 */
	public function GetLocality() : string
	{
		return $this->subject['L'] ?? '';
	}
	
	/**
	 * Get the organization from the subject
	 *
	 * @return string
	 */
	public function GetOrganization() : string
	{
		return $this->subject['O'] ?? '';
	}
	
	/**
	 * Get the organization unit from the subject
	 *
	 * @return string
	 */
	public function GetOrganizationUnit() : string
	{
		return $this->subject['OU'] ?? '';
	}
	
	/**
	 * Get the common name from the subject
	 *
	 * @return string
	 */
	public function GetCommonName() : string
	{
		return $this->subject['CN'] ?? '';
	}
	
	/**
	 * Get the email from the subject
	 *
	 * @return string
	 */
	public function GetEmail() : string
	{
		return $this->subject['emailAddress'] ?? '';
	}
	
	/**
	 * Get the OpenSSL key type integer
	 *
	 * @return int
	 */
	public function GetKeyType() : int
	{
		return $this->key;
	}
	
	/**
	 * Get the key type as string
	 *
	 * @return string
	 */
	public function GetKeyTypeString() : string
	{
		return match ($this->key)
		{
			OPENSSL_KEYTYPE_RSA => 'RSA',
			OPENSSL_KEYTYPE_DSA => 'DSA',
			OPENSSL_KEYTYPE_DH => 'DH',
			OPENSSL_KEYTYPE_EC => 'EC',
			default => 'Unknown',
		};
	}
	
	/**
	 * Get the key size in bits
	 *
	 * @return int
	 */
	public function GetKeyBits() : int
	{
		return $this->bits;
	}
	
	/**
	 * Get the certificate signing request in PEM format
	 *
	 * @return string
	 */
	public function GetPEM() : string
	{
		return $this->pem;
	}
	
	/**
	 * Get the SANs from the certificate
	 *
	 * @return array
	 */
	#[ArrayShape(['DNS' => "array", 'IP Address' => "array", 'email' => "array"])]
	public function GetSANs() : array
	{
		return $this->sans;
	}
	
	/**
	 * Get the SAN fields from CSR text
	 *
	 * @throws FileSystemException
	 *    In case of unable to use temporary file
	 *
	 * @throws CommandException
	 *    In case of unable to execute openssl command
	 */
	protected function ReadSANs() : void
	{
		// Write the CSR to a temporary file
		$temp_csr = \tempnam(\sys_get_temp_dir(), 'csr');
		if ($temp_csr === FALSE)
		{
			throw new FileSystemException(\_('Unable to create a temporary file'));
		}
		
		if (\file_put_contents($temp_csr, $this->pem) === FALSE)
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
		foreach ($this->ParseSAN($output) as $item => $value)
		{
			$sans[$item][] = $value;
		}
		
		$this->sans = $sans;
	}
	
	/**
	 * Parse the SAN fields from the OpenSSL output
	 *
	 * @param string $data
	 *    The output data
	 *
	 * @return \Generator
	 */
	private function ParseSAN(string $data) : \Generator
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
			if (!str_contains($san, ':'))
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
