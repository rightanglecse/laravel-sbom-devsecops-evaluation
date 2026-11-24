<?php

namespace App\Providers;

use Illuminate\Foundation\Http\Middleware\ValidateCsrfToken;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\ServiceProvider;

class ClinicServiceProvider extends ServiceProvider
{
    public function boot(): void
    {
        ValidateCsrfToken::except(['clinic/*']);

        Route::middleware('web')->group(base_path('routes/clinic.php'));
    }
}
