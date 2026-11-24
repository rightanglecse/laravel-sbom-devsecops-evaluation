<?php

use App\Http\Controllers\Clinic\ClinicInvoiceController;
use App\Http\Controllers\Clinic\ClinicNoteController;
use App\Http\Controllers\Clinic\ClinicReportController;
use App\Http\Controllers\Clinic\PatientRecordController;
use App\Http\Controllers\Clinic\StaffProfileController;
use Illuminate\Support\Facades\Route;

Route::middleware('auth')->prefix('clinic')->group(function () {
    Route::get('patients', [PatientRecordController::class, 'index']);
    Route::get('patients/search', [PatientRecordController::class, 'search']);
    Route::get('patients/lookup', [PatientRecordController::class, 'lookup']);
    Route::put('patients/{patient}', [PatientRecordController::class, 'update']);

    Route::get('invoices/filter', [ClinicInvoiceController::class, 'filter']);
    Route::post('invoices', [ClinicInvoiceController::class, 'store']);
    Route::get('invoices/{invoice}', [ClinicInvoiceController::class, 'show']);

    Route::post('notes', [ClinicNoteController::class, 'store']);
    Route::get('notes/{note}', [ClinicNoteController::class, 'show']);

    Route::put('profile', [StaffProfileController::class, 'update']);

    Route::get('reports/summary', [ClinicReportController::class, 'summary']);
    Route::get('reports/download', [ClinicReportController::class, 'download']);
});
