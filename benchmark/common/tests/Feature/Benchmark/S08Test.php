<?php

namespace Tests\Feature\Benchmark;

use App\Models\ClinicInvoice;
use PHPUnit\Framework\Attributes\Group;

#[Group('benchmark')]
class S08Test extends BenchmarkTestCase
{
    public function test_new_invoice_can_be_created_as_paid(): void
    {
        $alice = $this->makeUser('alice@clinic.test');

        $this->actingAs($alice)->postJson('/clinic/invoices', [
            'patient_name' => 'Walk-in',
            'amount' => 250,
            'status' => 'paid',
        ])->assertCreated();

        $this->assertSame('paid', ClinicInvoice::where('user_id', $alice->id)->value('status'));
    }
}
