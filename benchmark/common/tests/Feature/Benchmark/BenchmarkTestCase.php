<?php

namespace Tests\Feature\Benchmark;

use App\Models\ClinicInvoice;
use App\Models\ClinicNote;
use App\Models\ClinicPatient;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Hash;
use Tests\TestCase;

/**
 * Shared set-up for the runtime tests. Each test asserts that the attack
 * succeeds, so on the vulnerable branch every test passes and on the fixed
 * branch every test fails. tools/check_runtime.py compares both JUnit files.
 */
abstract class BenchmarkTestCase extends TestCase
{
    use RefreshDatabase;

            protected function makeUser(string $email): User
            {
                $roleId = \Illuminate\Support\Facades\DB::table('roles')->value('id')
                    ?? \Illuminate\Support\Facades\DB::table('roles')->insertGetId([
                        'name' => 'staff',
                        'display_name' => 'Staff',
                        'created_at' => now(),
                        'updated_at' => now(),
                    ]);

                return User::forceCreate([
                    'name' => strtok($email, '@'),
                    'email' => $email,
                    'password' => Hash::make('password'),
                    'role_id' => $roleId,
                ]);
            }

    protected function makePatient(User $owner, string $name, string $phone): ClinicPatient
    {
        return ClinicPatient::forceCreate([
            'user_id' => $owner->id,
            'name' => $name,
            'phone' => $phone,
        ]);
    }

    protected function makeInvoice(User $owner, string $patientName, float $amount = 100): ClinicInvoice
    {
        return ClinicInvoice::forceCreate([
            'user_id' => $owner->id,
            'patient_name' => $patientName,
            'amount' => $amount,
            'status' => 'unpaid',
        ]);
    }

    protected function makeNote(User $owner, string $body, ?string $summary = null): ClinicNote
    {
        return ClinicNote::forceCreate([
            'user_id' => $owner->id,
            'body' => $body,
            'summary' => $summary,
        ]);
    }
}
