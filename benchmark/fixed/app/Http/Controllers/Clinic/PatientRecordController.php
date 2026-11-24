<?php

namespace App\Http\Controllers\Clinic;

use App\Http\Controllers\Controller;
use App\Models\ClinicPatient;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Gate;

class PatientRecordController extends Controller
{
    public function index(Request $request)
    {
        $requested = $request->input('sort', 'name');
        $sort = in_array($requested, ['name', 'created_at'], true) ? $requested : 'name';

        $patients = ClinicPatient::where('user_id', $request->user()->id)
            ->orderBy($sort)
            ->get(['id', 'name', 'phone']);

        return response()->json($patients);
    }

    public function search(Request $request)
    {
        $userId = (int) $request->user()->id;
        $name = $request->input('name', '');

        $patients = DB::select(
            'SELECT id, name, phone FROM clinic_patients WHERE user_id = ? AND name = ?',
            [$userId, $name]
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
            return response('<p>No patient found for: ' . e($query) . '</p>');
        }

        return response('<p>Patient found.</p>');
    }

    public function update(Request $request, ClinicPatient $patient)
    {
        Gate::authorize('update', $patient);

        $data = $request->validate(['phone' => 'required|string|max:30']);

        $patient->update($data);

        return response()->json($patient);
    }
}
