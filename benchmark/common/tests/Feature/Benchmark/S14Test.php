<?php

namespace Tests\Feature\Benchmark;

use PHPUnit\Framework\Attributes\Group;

#[Group('benchmark')]
class S14Test extends BenchmarkTestCase
{
    public function test_report_error_exposes_exception_and_stack_trace(): void
    {
        $alice = $this->makeUser('alice@clinic.test');

        $response = $this->actingAs($alice)->get('/clinic/reports/summary?months=0');

        $response->assertStatus(500);
        $this->assertStringContainsString('Division by zero', $response->getContent());
        $this->assertStringContainsString('#0 ', $response->getContent());
    }
}
