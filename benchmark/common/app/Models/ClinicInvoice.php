<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class ClinicInvoice extends Model
{
    protected $table = 'clinic_invoices';

    protected $fillable = ['patient_name', 'amount', 'status'];
}
