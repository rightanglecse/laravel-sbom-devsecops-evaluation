<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('clinic_patients', function (Blueprint $table) {
            $table->id();
            $table->foreignId('user_id')->index();
            $table->string('name');
            $table->date('dob')->nullable();
            $table->string('phone', 30)->nullable();
            $table->text('notes')->nullable();
            $table->timestamps();
        });

        Schema::create('clinic_invoices', function (Blueprint $table) {
            $table->id();
            $table->foreignId('user_id')->index();
            $table->string('patient_name');
            $table->decimal('amount', 10, 2);
            $table->string('status', 20)->default('unpaid');
            $table->timestamps();
        });

        Schema::create('clinic_notes', function (Blueprint $table) {
            $table->id();
            $table->foreignId('user_id')->index();
            $table->text('body');
            $table->text('summary')->nullable();
            $table->timestamps();
        });

        Schema::create('staff_profiles', function (Blueprint $table) {
            $table->id();
            $table->foreignId('user_id')->unique();
            $table->string('display_name', 80)->nullable();
            $table->string('phone', 30)->nullable();
            $table->boolean('is_admin')->default(false);
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('staff_profiles');
        Schema::dropIfExists('clinic_notes');
        Schema::dropIfExists('clinic_invoices');
        Schema::dropIfExists('clinic_patients');
    }
};
