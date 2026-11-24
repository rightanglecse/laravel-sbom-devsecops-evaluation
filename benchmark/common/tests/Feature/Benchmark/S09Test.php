<?php

namespace Tests\Feature\Benchmark;

use PHPUnit\Framework\Attributes\Group;

#[Group('benchmark')]
class S09Test extends BenchmarkTestCase
{
    public function test_user_can_read_another_users_invoice(): void
    {
        $alice = $this->makeUser('alice@clinic.test');
        $bob = $this->makeUser('bob@clinic.test');
        $invoice = $this->makeInvoice($alice, 'Alice Private Invoice');

        $this->actingAs($bob)
            ->getJson('/clinic/invoices/' . $invoice->id)
            ->assertOk()
            ->assertJsonPath('patient_name', 'Alice Private Invoice');
    }
}
