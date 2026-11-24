<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class StaffProfile extends Model
{
    protected $table = 'staff_profiles';

    protected $fillable = ['display_name', 'phone'];

    protected $casts = ['is_admin' => 'boolean'];
}
