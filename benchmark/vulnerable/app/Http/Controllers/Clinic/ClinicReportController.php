<?php

namespace App\Http\Controllers\Clinic;

use App\Http\Controllers\Controller;
use App\Models\ClinicInvoice;
use Illuminate\Http\Request;

class ClinicReportController extends Controller
{
    public function summary(Request $request)
    {
        try {
            $months = $request->integer('months', 1);
            $total = (float) ClinicInvoice::where('user_id', $request->user()->id)->sum('amount');
            $average = intdiv((int) $total, $months);

            return response()->json(['total' => $total, 'monthly_average' => $average]);
        } catch (\Throwable $e) {
            if (config('clinic.debug_reports')) {
                return response($e->getMessage() . "\n" . $e->getTraceAsString(), 500);
            }

            throw $e;
        }
    }

    public function download(Request $request)
    {
        $file = $request->input('file', '');
        $path = storage_path('app/reports/' . $file);

        if (! is_file($path)) {
            abort(404);
        }

        return response(file_get_contents($path), 200, ['Content-Type' => 'text/plain']);
    }
}
