<?php

return [
    'storage' => [
        'key' => env('CLINIC_STORAGE_KEY'),
        'secret' => env('CLINIC_STORAGE_SECRET'),
        'region' => env('CLINIC_STORAGE_REGION', 'ap-south-1'),
    ],
];
