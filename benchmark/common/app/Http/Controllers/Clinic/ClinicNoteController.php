<?php

namespace App\Http\Controllers\Clinic;

use App\Http\Controllers\Controller;
use App\Models\ClinicNote;
use Illuminate\Http\Request;

class ClinicNoteController extends Controller
{
    public function store(Request $request)
    {
        $data = $request->validate([
            'body' => 'required|string|max:5000',
            'summary' => 'nullable|string|max:5000',
        ]);

        $note = new ClinicNote($data);
        $note->user_id = $request->user()->id;
        $note->save();

        return response()->json($note, 201);
    }

    public function show(Request $request, ClinicNote $note)
    {
        abort_unless((int) $note->user_id === (int) $request->user()->id, 404);

        return view('clinic.notes.show', ['note' => $note]);
    }
}
