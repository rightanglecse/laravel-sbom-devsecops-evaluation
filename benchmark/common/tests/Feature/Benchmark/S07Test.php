<?php

namespace Tests\Feature\Benchmark;

use App\Models\StaffProfile;
use PHPUnit\Framework\Attributes\Group;

#[Group('benchmark')]
class S07Test extends BenchmarkTestCase
{
    public function test_profile_update_can_set_admin_flag(): void
    {
        $alice = $this->makeUser('alice@clinic.test');

        $this->actingAs($alice)->putJson('/clinic/profile', [
            'display_name' => 'Alice',
            'is_admin' => true,
        ]);

        $profile = StaffProfile::where('user_id', $alice->id)->first();
        $this->assertNotNull($profile);
        $this->assertTrue((bool) $profile->is_admin);
    }
}
