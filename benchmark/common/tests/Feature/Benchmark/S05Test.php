<?php

namespace Tests\Feature\Benchmark;

use PHPUnit\Framework\Attributes\Group;

#[Group('benchmark')]
class S05Test extends BenchmarkTestCase
{
    public function test_markdown_summary_passes_raw_html(): void
    {
        $alice = $this->makeUser('alice@clinic.test');
        $note = $this->makeNote($alice, 'plain body', '<img src=x onerror=alert(5)>');

        $this->actingAs($alice)
            ->get('/clinic/notes/' . $note->id)
            ->assertOk()
            ->assertSee('<img src=x onerror=alert(5)>', false);
    }
}
