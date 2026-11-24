<?php

namespace Tests\Feature\Benchmark;

use PHPUnit\Framework\Attributes\Group;

#[Group('benchmark')]
class S04Test extends BenchmarkTestCase
{
    public function test_note_body_is_rendered_without_escaping(): void
    {
        $alice = $this->makeUser('alice@clinic.test');
        $note = $this->makeNote($alice, '<script>alert("s04")</script>');

        $this->actingAs($alice)
            ->get('/clinic/notes/' . $note->id)
            ->assertOk()
            ->assertSee('<script>alert("s04")</script>', false);
    }
}
