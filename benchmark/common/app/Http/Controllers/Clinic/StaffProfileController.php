<?php

namespace App\Http\Controllers\Clinic;

use App\Http\Controllers\Controller;
use App\Models\StaffProfile;
use Illuminate\Http\Request;

class StaffProfileController extends Controller
{
    public function update(Request $request)
    {
        $request->validate([
            'display_name' => 'sometimes|string|max:80',
            'phone' => 'sometimes|string|max:30',
        ]);

        $profile = StaffProfile::where('user_id', $request->user()->id)->first() ?? new StaffProfile();
        $profile->user_id = $request->user()->id;
        $profile->fill($request->except(['_token', '_method']));
        $profile->save();

        return response()->json($profile->fresh());
    }
}
