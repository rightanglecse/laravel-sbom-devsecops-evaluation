<?php

namespace Tests\Feature\Benchmark;

use PHPUnit\Framework\Attributes\Group;

#[Group('benchmark')]
class S12Test extends BenchmarkTestCase
{
    public function test_storage_key_exists_without_any_environment_configuration(): void
    {
        $this->assertNotEmpty(config('clinic.storage.key'));
        $this->assertNotEmpty(config('clinic.storage.secret'));
    }
}
