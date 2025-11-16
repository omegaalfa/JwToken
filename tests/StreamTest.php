<?php


use Omegaalfa\Jwtoken\Stream;
use PHPUnit\Framework\TestCase;

class StreamTest extends TestCase
{
    public function testWriteReadTellAndSize(): void
    {
        $stream = new Stream('php://temp', 'w+b');
        $this->assertTrue($stream->isWritable());
        $written = $stream->write('hello');
        $this->assertEquals(5, $written);


// rewind and read
        $stream->rewind();
        $this->assertTrue($stream->isReadable());
        $contents = $stream->getContents();
        $this->assertEquals('hello', $contents);


        $size = $stream->getSize();
        $this->assertIsInt($size);
        $this->assertGreaterThanOrEqual(0, $size);
    }


    public function testSeekAndTell(): void
    {
        $stream = new Stream('php://temp', 'w+b');
        $stream->write('abcdef');
        $stream->seek(2);
        $this->assertEquals(2, $stream->tell());


        $stream->rewind();
        $this->assertEquals(0, $stream->tell());
    }


    public function testDetachAndClose(): void
    {
        $stream = new Stream('php://temp', 'w+b');
        $resource = $stream->detach();
        $this->assertIsResource($resource);
// after detach resource is detached
        $this->assertTrue($stream->eof());


// closing should be a no-op now (no exception)
        $stream->close();
    }


    public function testReadLines(): void
    {
        $stream = new Stream('php://temp', 'w+b');
        $stream->write("line1\nline2\n");
        $stream->rewind();


        $lines = [];
        foreach ($stream->readLines() as $line) {
            $lines[] = trim((string)$line);
        }


        $this->assertEquals(['line1', 'line2'], $lines);
    }


    public function testReadCsv(): void
    {
        $stream = new Stream('php://temp', 'w+b');
        $stream->write("a,b,c\n1,2,3\n");
        $stream->rewind();


        $rows = [];
        foreach ($stream->readLinesCsv() as $row) {
            if ($row === false || $row === null) {
                continue;
            }
            $rows[] = $row;
        }


        $this->assertCount(2, $rows);
        $this->assertEquals(['a','b','c'], $rows[0]);
    }


    public function testMetadataAndMode(): void
    {
        $stream = new Stream('php://temp', 'w+b');
        $meta = $stream->getMetadata();
        $this->assertIsArray($meta);
        $this->assertArrayHasKey('mode', $meta);
        $this->assertIsString($stream->getMetadata('mode'));
    }
}