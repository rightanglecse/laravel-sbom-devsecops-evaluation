<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>Clinical note</title>
</head>
<body>
    <h1>Clinical note #{{ $note->id }}</h1>
    <section class="note-body">{!! $note->body !!}</section>
    <section class="note-summary">{!! \Illuminate\Support\Str::markdown($note->summary ?? '') !!}</section>
</body>
</html>
