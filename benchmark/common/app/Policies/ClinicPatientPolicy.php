<?php

namespace App\Policies;

use App\Models\ClinicPatient;
use App\Models\User;

class ClinicPatientPolicy
{
    public function update(User $user, ClinicPatient $patient): bool
    {
        return (int) $patient->user_id === (int) $user->id;
    }
}
