<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class ClinicNote extends Model
{
    protected $table = 'clinic_notes';

    protected $fillable = ['body', 'summary'];
}
