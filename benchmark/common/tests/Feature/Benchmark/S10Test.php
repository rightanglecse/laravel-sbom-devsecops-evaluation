<?php

namespace Tests\Feature\Benchmark;

use App\Models\ClinicPatient;
use PHPUnit\Framework\Attributes\Group;

#[Group('benchmark')]
class S10Test extends BenchmarkTestCase
{
    public function test_user_can_update_another_users_patient(): void
    {
        $alice = $this->makeUser('alice@clinic.test');
        $bob = $this->makeUser('bob@clinic.test');
        $patient = $this->makePatient($alice, 'Alice Patient', '111');

        $this->actingAs($bob)
            ->putJson('/clinic/patients/' . $patient->id, ['phone' => '000'])
            ->assertOk();

        $this->assertSame('000', ClinicPatient::find($patient->id)->phone);
    }
}
