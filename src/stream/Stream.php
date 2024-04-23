<?php


namespace omegalfa\jwtoken\stream;


use Generator;
use InvalidArgumentException;
use Psr\Http\Message\StreamInterface;
use RuntimeException;


/**
 * Class Stream
 *
 * @package src\stream
 */
class Stream implements StreamInterface
{

	/**
	 * @var resource
	 */
	protected $stream;

	/**
	 * @var resource
	 */
	protected $resource;

	/**
	 * @var array
	 */
	protected array $meta;


	/**
	 * @var array
	 */
	protected array $modes = [
			'readable' => ['r', 'r+', 'w+', 'a+', 'x+', 'c+'],
			'writable' => ['r+', 'w', 'w+', 'a', 'a+', 'x', 'x+', 'c', 'c+'],
	];


	/**
	 * @param  string  $stream
	 * @param  string  $mode
	 */
	public function __construct(string $stream = 'php://temp', string $mode = 'r')
	{
		$this->attach($stream, $mode);
	}


	/**
	 * @param          $resource
	 * @param  string  $mode
	 *
	 * @return void
	 */
	public function attach($resource, string $mode = 'rb'): void
	{
		if(is_string($resource)) {
			if(!file_exists($resource)) {
				$resource = fopen($resource, 'wb');
			} else {
				$resource = fopen($resource, $mode);
			}
		}

		if(!is_resource($resource)) {
			throw new InvalidArgumentException('Must be a string flow identifier or flow resource');
		}

		$this->resource = $resource;
	}

	/**
	 * @param $resource
	 *
	 * @return void
	 */
	public function addResource($resource): void
	{
		if(!is_resource($resource)) {
			throw new InvalidArgumentException('Must be a string flow identifier or flow resource');
		}


		$this->resource = $resource;
	}


	/**
	 * @return string
	 */
	public function __toString(): string
	{
		if(!$this->isReadable()) {
			return '';
		}
		try {
			if($this->isSeekable()) {
				$this->rewind();
			}
			return $this->getContents();
		} catch(RuntimeException) {
			return '';
		}
	}


	/**
	 * @return bool
	 */
	public function isReadable(): bool
	{
		$this->meta = stream_get_meta_data($this->resource);

		foreach($this->modes['readable'] as $mode) {
			if(str_starts_with($this->meta['mode'], $mode)) {
				return true;
			}
		}

		return false;
	}


	/**
	 * @return bool
	 */
	public function isSeekable(): bool
	{
		if(!$this->resource) {
			return false;
		}

		$this->meta = stream_get_meta_data($this->resource);

		return $this->meta['seekable'];
	}

	/**
	 * @return void
	 */
	public function rewind(): void
	{
		$this->seek(0);
	}

	/**
	 * @param  int  $offset
	 * @param  int  $whence
	 *
	 * @return bool
	 */
	public function seek(int $offset, int $whence = SEEK_SET): bool
	{
		if(!$this->isSeekable() || fseek($this->resource, $offset, $whence) === -1) {
			throw new RuntimeException('Não foi possível procurar no fluxo (stream)');
		}

		return true;
	}


	/**
	 * @return string
	 */
	public function getContents(): string
	{
		if(!$this->isReadable() || ($contents = stream_get_contents($this->resource)) === false) {
			throw new RuntimeException('Não foi possível obter conteúdo do stream');
		}

		return $contents;
	}


	/**
	 * @return bool
	 */
	public function isWritable(): bool
	{
		$meta = stream_get_meta_data($this->resource);

		foreach($this->modes['writable'] as $mode) {
			if(str_starts_with($meta['mode'], $mode)) {
				return true;
			}
		}

		return false;
	}


	/**
	 * @param  int  $length
	 *
	 * @return string
	 */
	public function read(int $length): string
	{
		if(!$this->isReadable()) {
			throw new RuntimeException('Stream (fluxo) não é legível');
		}

		$read = fread($this->resource, $length);

		if($read === false) {
			throw new RuntimeException('Não foi possível ler conteúdo do stream');
		}

		return $read;
	}


	/**
	 * @param  string  $string
	 *
	 * @return int
	 */
	public function write(string $string): int
	{
		$write = fwrite($this->resource, $string);

		if(!$this->isWritable()) {
			throw new RuntimeException('O stream (fluxo) não tem permissão de escrita.');
		}
		if($write === false) {
			throw new RuntimeException('Não foi possível escrever no stream (fluxo).');
		}

		return $write;
	}


	/**
	 * @return int|null
	 */
	public function getSize(): int|null
	{
		if($this->validResource($this->resource)) {
			throw new RuntimeException('Error resource invalid');
		}

		$stats = fstat($this->resource);

		if(!$stats) {
			return null;
		}

		return $stats['size'];
	}

	/**
	 * @param $resource
	 *
	 * @return bool
	 */
	public function validResource($resource): bool
	{
		if(!is_resource($resource)) {
			return false;
		}

		return true;
	}


	/**
	 * @return int
	 */
	public function tell(): int
	{
		$resource = $this->resource;
		$posCurrent = ftell($resource);

		if(!is_int($posCurrent)) {
			throw new RuntimeException('Error occurred during tell operation');
		}

		return $posCurrent;
	}


	/**
	 * @param  string|null  $key
	 *
	 * @return mixed
	 */
	public function getMetadata(string $key = null): mixed
	{
		$this->meta = stream_get_meta_data($this->resource);

		if(is_null($key) === true) {
			return $this->meta;
		}

		return $this->meta[$key] ?? null;
	}


	/**
	 * @return int
	 */
	public function countLines(): int
	{
		$line = 0;
		if(!$this->isReadable()) {
			throw new RuntimeException('Stream (fluxo) não é legível');
		}

		while($this->eof() === false) {
			fgets($this->resource);
			++$line;
		}

		$this->rewind();
		return $line;
	}

	/**
	 * @return bool
	 */
	public function eof(): bool
	{
		return feof($this->resource);
	}


	/**
	 * @return Generator
	 */
	public function readLines(): Generator
	{
		if(!$this->isReadable()) {
			throw new RuntimeException('Stream (fluxo) não é legível');
		}

		while($this->eof() === false) {
			yield fgets($this->resource);
		}

		$this->close();
	}


	/**
	 * @param  int|null  $length
	 * @param  string    $separator
	 * @param  string    $enclosure
	 * @param  string    $escape
	 *
	 * @return Generator
	 */
	public function readLinesCsv(?int $length = 0, string $separator = ',', string $enclosure = '"', string $escape = '\\'): Generator
	{
		if(!$this->isReadable()) {
			throw new RuntimeException('Stream (fluxo) não é legível');
		}

		while($this->eof() === false) {
			yield fgetcsv($this->resource, $length, $separator, $enclosure, $escape);
		}

		$this->close();
	}


	/**
	 * @param  int  $line
	 *
	 * @return mixed
	 */
	public function readLineCsv(int $line = 0): mixed
	{
		if(!$this->isReadable()) {
			throw new RuntimeException('Stream (fluxo) não é legível');
		}

		$data = fgetcsv($this->resource);

		if(!is_array($data)) {
			return [];
		}

		return $data[$line] ?? null;
	}


	/**
	 * @return void
	 */
	public function close(): void
	{
		if(!$this->resource) {
			return;
		}

		$resource = $this->detach();

		if($this->validResource($this->resource)) {
			fclose($this->resource);
		}

		fclose($resource);
	}


	/**
	 * @return resource|null
	 */
	public function detach()
	{
		$resource = $this->resource;

		unset($this->resource);
		$this->resource = null;

		return $resource;
	}


	/**
	 *
	 */
	public function __destruct()
	{
		$this->close();
	}
}
