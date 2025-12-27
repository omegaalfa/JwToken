<?php


use Omegaalfa\Jwtoken\Stream;
use PHPUnit\Framework\TestCase;

class StreamTest extends TestCase
{
    private string $tempFile;

    protected function setUp(): void
    {
        $this->tempFile = sys_get_temp_dir() . '/stream_test_' . uniqid() . '.txt';
    }

    protected function tearDown(): void
    {
        if (file_exists($this->tempFile)) {
            @unlink($this->tempFile);
        }
    }

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

    public function testToString(): void
    {
        $stream = new Stream('php://temp', 'r+');
        $stream->write('Content for __toString');
        $this->assertEquals('Content for __toString', (string)$stream);
    }

    public function testIsSeekable(): void
    {
        $stream = new Stream('php://temp', 'r+');
        $this->assertTrue($stream->isSeekable());
    }

    public function testEof(): void
    {
        $stream = new Stream('php://temp', 'r+');
        $stream->write('EOF test');
        
        $stream->rewind();
        $this->assertFalse($stream->eof());
        
        $stream->getContents();
        $this->assertTrue($stream->eof());
    }

    public function testCountLines(): void
    {
        $stream = new Stream('php://temp', 'r+');
        $stream->write("Line 1\nLine 2\nLine 3");
        
        $stream->rewind();
        $lineCount = $stream->countLines();
        
        $this->assertEquals(3, $lineCount);
    }

    public function testReadLineCsv(): void
    {
        $stream = new Stream('php://temp', 'r+');
        $stream->write("col1,col2,col3\nval1,val2,val3");
        
        $stream->rewind();
        $firstValue = $stream->readLineCsv(0);
        $this->assertEquals('col1', $firstValue);
    }

    public function testAttachWithFile(): void
    {
        file_put_contents($this->tempFile, 'Test content');
        
        $stream = new Stream($this->tempFile, 'r');
        $this->assertTrue($stream->isReadable());
        $this->assertEquals('Test content', $stream->getContents());
    }

    public function testAddResource(): void
    {
        $resource = fopen('php://temp', 'r+');
        fwrite($resource, 'Resource test');
        
        $stream = new Stream('php://temp', 'r');
        $stream->addResource($resource);
        
        rewind($resource);
        $stream->rewind();
        $this->assertEquals('Resource test', $stream->getContents());
    }

    public function testAddResourceThrowsExceptionForInvalidResource(): void
    {
        $stream = new Stream('php://temp', 'r');
        
        $this->expectException(\InvalidArgumentException::class);
        $stream->addResource('not a resource');
    }

    public function testAttachThrowsExceptionForInvalidResource(): void
    {
        $stream = new Stream('php://temp', 'r');
        
        $this->expectException(\InvalidArgumentException::class);
        $stream->attach(12345);
    }

    public function testSeekThrowsExceptionWhenNotSeekable(): void
    {
        $stream = new Stream('php://output', 'w');
        
        $this->expectException(\RuntimeException::class);
        $stream->seek(0);
    }

    public function testGetSizeThrowsExceptionForInvalidResource(): void
    {
        $stream = new Stream('php://temp', 'r');
        $stream->close();
        
        $this->expectException(\RuntimeException::class);
        $stream->getSize();
    }

    public function testTellThrowsExceptionForInvalidResource(): void
    {
        $stream = new Stream('php://temp', 'r');
        $stream->close();
        
        $this->expectException(\RuntimeException::class);
        $stream->tell();
    }

    public function testGetMetadataReturnsNullForInvalidResource(): void
    {
        $stream = new Stream('php://temp', 'r');
        $stream->close();
        
        $this->assertNull($stream->getMetadata());
    }

    public function testToStringReturnsEmptyForNonReadable(): void
    {
        $stream = new Stream('php://temp', 'w');
        
        $this->assertEquals('', (string)$stream);
    }

    public function testReadLineCsvReturnsEmptyArrayWhenNoData(): void
    {
        $stream = new Stream('php://temp', 'r+');
        $stream->write('');
        $stream->rewind();
        
        $result = $stream->readLineCsv();
        $this->assertEquals([], $result);
    }

    public function testRead(): void
    {
        $stream = new Stream('php://temp', 'r+');
        $content = '0123456789';
        $stream->write($content);
        $stream->rewind();
        
        $chunk = $stream->read(5);
        $this->assertEquals('01234', $chunk);
    }
}