<?php

namespace App\Http\Controllers\Clinic;

use App\Http\Controllers\Controller;
use App\Models\ClinicInvoice;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Gate;

class ClinicInvoiceController extends Controller
{
    public function filter(Request $request)
    {
        $status = $request->input('status', 'unpaid');

        $invoices = ClinicInvoice::where('user_id', $request->user()->id)
            ->whereRaw('status = ?', [$status])
            ->get();

        return response()->json($invoices);
    }

    public function store(Request $request)
    {
        $data = $request->validate([
            'patient_name' => 'required|string|max:120',
            'amount' => 'required|numeric|min:0',
        ]);

        $invoice = new ClinicInvoice($data);
        $invoice->user_id = $request->user()->id;
        $invoice->save();

        return response()->json($invoice->fresh(), 201);
    }

    public function show(Request $request, ClinicInvoice $invoice)
    {
        Gate::authorize('view', $invoice);

        return response()->json($invoice);
    }
}
