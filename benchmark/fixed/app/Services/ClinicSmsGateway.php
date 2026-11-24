<?php

namespace App\Services;

class ClinicSmsGateway
{
    private string $apiKey;

    private string $apiSecret;

    public function __construct()
    {
        $this->apiKey = (string) config('services.clinic_sms.key', '');
        $this->apiSecret = (string) config('services.clinic_sms.secret', '');
    }

    public function credentialsConfigured(): bool
    {
        return $this->apiKey !== '' && $this->apiSecret !== '';
    }

    public function authHeader(): string
    {
        return 'Basic ' . base64_encode($this->apiKey . ':' . $this->apiSecret);
    }
}
