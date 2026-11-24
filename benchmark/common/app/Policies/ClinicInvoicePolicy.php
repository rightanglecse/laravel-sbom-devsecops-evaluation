<?php

namespace App\Policies;

use App\Models\ClinicInvoice;
use App\Models\User;

class ClinicInvoicePolicy
{
    public function view(User $user, ClinicInvoice $invoice): bool
    {
        return (int) $invoice->user_id === (int) $user->id;
    }
}
