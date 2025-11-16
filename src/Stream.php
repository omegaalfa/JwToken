<?php

declare(strict_types=1);


namespace Omegaalfa\Jwtoken;

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
     * @var resource|null
     */
    protected $stream;

    /**
     * @var resource|null
     */
    protected $resource;

    /**
     * @var array<string, mixed>
     */
    protected array $meta = [];

    /**
     * @var array<string, array<int, string>>
     */
    protected array $modes = [
        'readable' => ['r', 'r+', 'w+', 'a+', 'x+', 'c+'],
        'writable' => ['r+', 'w', 'w+', 'a', 'a+', 'x', 'x+', 'c', 'c+'],
    ];


    /**
     * @param string $stream
     * @param string $mode
     */
    public function __construct(string $stream = 'php://temp', string $mode = 'r')
    {
        $this->attach($stream, $mode);
    }


    /**
     * @param string|resource $resource
     * @param string $mode
     *
     * @return void
     */
    public function attach(mixed $resource, string $mode = 'rb'): void
    {
        if (is_string($resource)) {
            if (!file_exists($resource)) {
                $resource = fopen($resource, 'wb');
            } else {
                $resource = fopen($resource, $mode);
            }
        }

        if (!is_resource($resource)) {
            throw new InvalidArgumentException('Must be a string flow identifier or flow resource');
        }

        $this->resource = $resource;
    }

    /**
     * @param resource $resource
     * @return void
     */
    public function addResource(mixed $resource): void
    {
        if (!is_resource($resource)) {
            throw new InvalidArgumentException('Must be a string flow identifier or flow resource');
        }
        $this->resource = $resource;
    }


    /**
     * @return string
     */
    public function __toString(): string
    {
        if (!$this->isReadable()) {
            return '';
        }
        try {
            if ($this->isSeekable()) {
                $this->rewind();
            }
            return $this->getContents();
        } catch (RuntimeException) {
            return '';
        }
    }


    /**
     * @return bool
     */
    public function isReadable(): bool
    {
        if (!$this->validResource($this->resource)) {
            return false;
        }

        $this->meta = stream_get_meta_data($this->resource);
        $mode = $this->meta['mode'];

        return array_any($this->modes['readable'], static fn($modePrefix) => str_starts_with($mode, $modePrefix));

    }

    /**
     * @param resource|null $resource
     */
    public function validResource(mixed $resource): bool
    {
        return is_resource($resource);
    }

    /**
     * @return bool
     */
    public function isSeekable(): bool
    {
        if (!$this->validResource($this->resource)) {
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
     * @param int $offset
     * @param int $whence
     */
    public function seek(int $offset, int $whence = SEEK_SET): void
    {
        if (!$this->isSeekable() || fseek($this->resource, $offset, $whence) === -1) {
            throw new RuntimeException('Unable to seek in stream.');
        }
    }

    /**
     * @return string
     */
    public function getContents(): string
    {
        if (!$this->isReadable() || ($contents = stream_get_contents($this->resource)) === false) {
            throw new RuntimeException('Unable to read stream contents.');
        }

        return $contents;
    }

    /**
     * @param int<1, max> $length
     *
     * @return string
     */
    public function read(int $length): string
    {
        if (!$this->isReadable()) {
            throw new RuntimeException('Stream is not readable.');
        }

        $read = fread($this->resource, $length);

        if ($read === false) {
            throw new RuntimeException('Unable to read from stream.');
        }

        return $read;
    }

    /**
     * @param string $string
     *
     * @return int
     */
    public function write(string $string): int
    {
        if (!$this->isWritable()) {
            throw new RuntimeException('Stream is not writable.');
        }

        $write = fwrite($this->resource, $string);

        if ($write === false) {
            throw new RuntimeException('Unable to write to stream.');
        }

        return $write;
    }

    /**
     * @return bool
     */
    public function isWritable(): bool
    {
        if (!$this->validResource($this->resource)) {
            return false;
        }

        $meta = stream_get_meta_data($this->resource);
        $mode = $meta['mode'];

        return array_any($this->modes['writable'], static fn($modePrefix) => str_starts_with($mode, $modePrefix));

    }

    /**
     * @return int|null
     */
    public function getSize(): int|null
    {
        if (!$this->validResource($this->resource)) {
            throw new RuntimeException('Invalid stream resource.');
        }

        $stats = fstat($this->resource);

        if (!$stats) {
            return null;
        }

        return (int)$stats['size'];
    }

    /**
     * @return int
     */
    public function tell(): int
    {
        $resource = $this->resource;
        if (!$this->validResource($resource)) {
            throw new RuntimeException('Recurso inválido ao informar a posição.');
        }
        $posCurrent = ftell($resource);

        if (!is_int($posCurrent)) {
            throw new RuntimeException('Error occurred during tell operation');
        }

        return $posCurrent;
    }


    /**
     * @param string|null $key
     *
     * @return mixed
     */
    public function getMetadata(?string $key = null): mixed
    {
        if (!$this->validResource($this->resource)) {
            return null;
        }

        $this->meta = stream_get_meta_data($this->resource);

        if (is_null($key) === true) {
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
        if (!$this->isReadable()) {
            throw new RuntimeException('Stream is not readable.');
        }

        while ($this->eof() === false) {
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
        if (!$this->validResource($this->resource)) {
            return true;
        }

        return feof($this->resource);
    }


    /**
     * @return Generator
     */
    public function readLines(): Generator
    {
        if (!$this->isReadable()) {
            throw new RuntimeException('Stream is not readable.');
        }

        while ($this->eof() === false) {
            yield fgets($this->resource);
        }

        $this->close();
    }

    /**
     * @return void
     */
    public function close(): void
    {
        if (!$this->validResource($this->resource)) {
            return;
        }

        $resource = $this->detach();

        if ($this->validResource($resource)) {
            fclose($resource);
        }
    }

    /**
     * @return resource|null
     */
    public function detach()
    {
        $resource = $this->resource;
        $this->resource = null;

        return $resource;
    }

    /**
     * @param int<0, max>|null $length
     * @param string $separator
     * @param string $enclosure
     * @param string $escape
     *
     * @return Generator
     */
    public function readLinesCsv(?int $length = 0, string $separator = ',', string $enclosure = '"', string $escape = '\\'): Generator
    {
        if (!$this->isReadable()) {
            throw new RuntimeException('Stream is not readable.');
        }

        while ($this->eof() === false) {
            yield fgetcsv($this->resource, $length, $separator, $enclosure, $escape);
        }

        $this->close();
    }

    /**
     * @param int $line
     *
     * @return mixed
     */
    public function readLineCsv(int $line = 0): mixed
    {
        if (!$this->isReadable()) {
            throw new RuntimeException('Stream is not readable.');
        }

        $data = fgetcsv($this->resource);

        if (!is_array($data)) {
            return [];
        }

        return $data[$line] ?? null;
    }

    /**
     *
     */
    public function __destruct()
    {
        $this->close();
    }
}
