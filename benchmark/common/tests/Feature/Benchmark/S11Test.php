<?php

namespace Tests\Feature\Benchmark;

use App\Services\ClinicSmsGateway;
use PHPUnit\Framework\Attributes\Group;

#[Group('benchmark')]
class S11Test extends BenchmarkTestCase
{
    public function test_sms_credentials_exist_without_any_environment_configuration(): void
    {
        config(['services.clinic_sms' => null]);

        $this->assertTrue((new ClinicSmsGateway())->credentialsConfigured());
    }
}
