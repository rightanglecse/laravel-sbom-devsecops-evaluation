<?php

namespace Tests\Feature\Benchmark;

use PHPUnit\Framework\Attributes\Group;

#[Group('benchmark')]
class S06Test extends BenchmarkTestCase
{
    public function test_lookup_reflects_query_without_escaping(): void
    {
        $alice = $this->makeUser('alice@clinic.test');

        $this->actingAs($alice)
            ->get('/clinic/patients/lookup?q=' . urlencode('<script>alert(6)</script>'))
            ->assertOk()
            ->assertSee('<script>alert(6)</script>', false);
    }
}
