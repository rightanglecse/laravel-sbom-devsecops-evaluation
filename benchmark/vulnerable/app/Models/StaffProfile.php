<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class StaffProfile extends Model
{
    protected $table = 'staff_profiles';

    protected $guarded = [];

    protected $casts = ['is_admin' => 'boolean'];
}
