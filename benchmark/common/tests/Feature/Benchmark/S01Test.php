<?php

namespace Tests\Feature\Benchmark;

use PHPUnit\Framework\Attributes\Group;

#[Group('benchmark')]
class S01Test extends BenchmarkTestCase
{
    public function test_quote_payload_returns_other_users_patients(): void
    {
        $alice = $this->makeUser('alice@clinic.test');
        $bob = $this->makeUser('bob@clinic.test');
        $this->makePatient($bob, 'Bob Patient', '555');

        $response = $this->actingAs($alice)
            ->getJson('/clinic/patients/search?name=' . urlencode("x' OR '1'='1"));

        $response->assertOk();
        $this->assertContains('Bob Patient', array_column($response->json(), 'name'));
    }
}
