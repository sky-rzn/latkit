<?php
// phpredis scenarios (МR0): defaults only.
$host = getenv('REDIS_HOST') ?: '127.0.0.1';
$port = (int)(getenv('REDIS_PORT') ?: 6399);
$scenario = $argv[1] ?? 'basic';

$r = new Redis();
$r->connect($host, $port);

switch ($scenario) {
    case 'basic':
        $r->set('php:k', 'v');
        echo "get " . $r->get('php:k') . "\n";
        $r->incr('php:n');
        $r->hMSet('php:h', ['a' => '1', 'b' => '2']);
        echo "hgetall " . json_encode($r->hGetAll('php:h')) . "\n";
        echo "mget " . json_encode($r->mGet(['php:k', 'php:n', 'php:missing'])) . "\n";
        $r->del(['php:k', 'php:n', 'php:h']);
        break;
    case 'pipeline':
        $p = $r->pipeline();
        for ($i = 0; $i < 100; $i++) { $p->set("php:p:$i", "v$i"); }
        echo "pipeline " . count($p->exec()) . "\n";
        break;
    case 'multi':
        $res = $r->multi()->set('php:t:a', '1')->incr('php:t:n')->exec();
        echo "multi " . count($res) . "\n";
        break;
    default:
        fwrite(STDERR, "unknown scenario $scenario\n");
        exit(2);
}
$r->close();
