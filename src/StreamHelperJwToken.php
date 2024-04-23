<?php

namespace omegaalfa\jwtoken;

use Psr\Http\Message\StreamInterface;
use omegaalfa\jwtoken\stream\Stream;

trait StreamHelperJwToken
{

	/**
	 * @param  string  $file
	 *
	 * @return Stream
	 */
	private function instanceStream(string $file): StreamInterface
	{
		return new Stream($file);
	}

	/**
	 * @param  string  $file
	 *
	 * @return string
	 */
	protected function readFile(string $file): string
	{
		if(!file_exists($file)) {
			throw new \InvalidArgumentException("File {$file} does not exist or the path is invalid.");
		}

		return $this->instanceStream($file)->getContents();
	}
}
