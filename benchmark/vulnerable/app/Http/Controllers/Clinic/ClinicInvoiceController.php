<?php

namespace App\Http\Controllers\Clinic;

use App\Http\Controllers\Controller;
use App\Models\ClinicInvoice;
use Illuminate\Http\Request;

class ClinicInvoiceController extends Controller
{
    public function filter(Request $request)
    {
        $status = $request->input('status', 'unpaid');

        $invoices = ClinicInvoice::where('user_id', $request->user()->id)
            ->whereRaw("status = '" . $status . "'")
            ->get();

        return response()->json($invoices);
    }

    public function store(Request $request)
    {
        $request->validate([
            'patient_name' => 'required|string|max:120',
            'amount' => 'required|numeric|min:0',
        ]);

        $invoice = new ClinicInvoice($request->all());
        $invoice->user_id = $request->user()->id;
        $invoice->save();

        return response()->json($invoice->fresh(), 201);
    }

    public function show(Request $request, ClinicInvoice $invoice)
    {
        return response()->json($invoice);
    }
}
