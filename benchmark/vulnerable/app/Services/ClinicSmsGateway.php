<?php

namespace App\Services;

class ClinicSmsGateway
{
    private string $apiKey = 'SK7f3c9a1e5b2d4f6a8c0e9b7d5f3a1c2e';

    private string $apiSecret = 'Qm9vZ2llV29vZ2llMjAyNlNtc0dhdGV3YXk';

    public function credentialsConfigured(): bool
    {
        return $this->apiKey !== '' && $this->apiSecret !== '';
    }

    public function authHeader(): string
    {
        return 'Basic ' . base64_encode($this->apiKey . ':' . $this->apiSecret);
    }
}
