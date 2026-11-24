<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class ClinicPatient extends Model
{
    protected $table = 'clinic_patients';

    protected $fillable = ['name', 'dob', 'phone', 'notes'];
}
