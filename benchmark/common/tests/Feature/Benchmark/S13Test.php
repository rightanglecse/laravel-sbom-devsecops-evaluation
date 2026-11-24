<?php

namespace Tests\Feature\Benchmark;

use PHPUnit\Framework\Attributes\Group;

#[Group('benchmark')]
class S13Test extends BenchmarkTestCase
{
    public function test_state_changing_post_is_accepted_without_csrf_token(): void
    {
        // Laravel skips CSRF checks while the environment is "testing";
        // switch it off so the real middleware runs.
        $this->app['env'] = 'local';

        $alice = $this->makeUser('alice@clinic.test');

        $this->actingAs($alice)
            ->post('/clinic/notes', ['body' => 'posted from another site'])
            ->assertStatus(201);
    }
}
