<?php

namespace App\Http\Controllers\Clinic;

use App\Http\Controllers\Controller;
use App\Models\ClinicPatient;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;

class PatientRecordController extends Controller
{
    public function index(Request $request)
    {
        $sort = $request->input('sort', 'name');

        $patients = ClinicPatient::where('user_id', $request->user()->id)
            ->orderByRaw($sort)
            ->get(['id', 'name', 'phone']);

        return response()->json($patients);
    }

    public function search(Request $request)
    {
        $userId = (int) $request->user()->id;
        $name = $request->input('name', '');

        $patients = DB::select(
            "SELECT id, name, phone FROM clinic_patients WHERE user_id = " . $userId . " AND name = '" . $name . "'"
        );

        return response()->json($patients);
    }

    public function lookup(Request $request)
    {
        $query = $request->input('q', '');

        $found = ClinicPatient::where('user_id', $request->user()->id)
            ->where('name', $query)
            ->exists();

        if (! $found) {
            return response('<p>No patient found for: ' . $query . '</p>');
        }

        return response('<p>Patient found.</p>');
    }

    public function update(Request $request, ClinicPatient $patient)
    {
        $data = $request->validate(['phone' => 'required|string|max:30']);

        $patient->update($data);

        return response()->json($patient);
    }
}
