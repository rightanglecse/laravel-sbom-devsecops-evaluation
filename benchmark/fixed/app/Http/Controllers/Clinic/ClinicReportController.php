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
            report($e);

            return response()->json(['message' => 'The report could not be generated.'], 500);
        }
    }

    public function download(Request $request)
    {
        $file = basename((string) $request->input('file', ''));

        if (! preg_match('/^[A-Za-z0-9_-]+\.(csv|txt)$/', $file)) {
            abort(422);
        }

        $path = storage_path('app/reports/' . $file);

        if (! is_file($path)) {
            abort(404);
        }

        return response(file_get_contents($path), 200, ['Content-Type' => 'text/plain']);
    }
}
