<?php

namespace Tests\Feature\Benchmark;

use PHPUnit\Framework\Attributes\Group;

#[Group('benchmark')]
class S15Test extends BenchmarkTestCase
{
    private string $secretFile;

    protected function setUp(): void
    {
        parent::setUp();
        @mkdir(storage_path('app/reports'), 0777, true);
        $this->secretFile = storage_path('app/benchmark-private.txt');
        file_put_contents($this->secretFile, 'PRIVATE-S15');
    }

    protected function tearDown(): void
    {
        @unlink($this->secretFile);
        parent::tearDown();
    }

    public function test_download_reads_file_outside_reports_folder(): void
    {
        $alice = $this->makeUser('alice@clinic.test');

        $response = $this->actingAs($alice)->get('/clinic/reports/download?file=' . urlencode('../benchmark-private.txt'));

        $response->assertOk();
        $this->assertStringContainsString('PRIVATE-S15', $response->getContent());
    }
}
