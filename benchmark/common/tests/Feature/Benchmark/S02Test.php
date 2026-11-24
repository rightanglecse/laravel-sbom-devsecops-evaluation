<?php

namespace Tests\Feature\Benchmark;

use PHPUnit\Framework\Attributes\Group;

#[Group('benchmark')]
class S02Test extends BenchmarkTestCase
{
    public function test_quote_payload_in_status_filter_returns_other_users_invoices(): void
    {
        $alice = $this->makeUser('alice@clinic.test');
        $bob = $this->makeUser('bob@clinic.test');
        $this->makeInvoice($bob, 'Bob Invoice');

        $response = $this->actingAs($alice)
            ->getJson('/clinic/invoices/filter?status=' . urlencode("x' OR '1'='1"));

        $response->assertOk();
        $this->assertContains('Bob Invoice', array_column($response->json(), 'patient_name'));
    }
}
