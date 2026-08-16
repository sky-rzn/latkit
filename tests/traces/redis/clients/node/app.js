// node-redis scenarios (МR0): defaults only — the point is what the library
// negotiates and how it batches when the application says nothing.
const { createClient } = require('redis');

const url = `redis://${process.env.REDIS_HOST || '127.0.0.1'}:${process.env.REDIS_PORT || 6399}`;
const scenario = process.argv[2] || 'basic';

async function main() {
  if (scenario === 'resp3') {
    const c = createClient({ url, RESP: 3 });
    await c.connect();
    await c.set('node:r3', 'v');
    console.log('get', await c.get('node:r3'));
    await c.quit();
    return;
  }
  const c = createClient({ url });
  await c.connect();
  if (scenario === 'basic') {
    await c.set('node:k', 'v');
    console.log('get', await c.get('node:k'));
    await c.incr('node:n');
    await c.hSet('node:h', { a: '1', b: '2' });
    console.log('hgetall', await c.hGetAll('node:h'));
    console.log('mget', await c.mGet(['node:k', 'node:n', 'node:missing']));
    await c.del(['node:k', 'node:n', 'node:h']);
  } else if (scenario === 'pipeline') {
    // node-redis auto-pipelines whatever is issued in one tick: no explicit
    // pipeline object, just concurrent promises.
    const ps = [];
    for (let i = 0; i < 100; i++) ps.push(c.set(`node:p:${i}`, `v${i}`));
    await Promise.all(ps);
    console.log('pipeline', ps.length);
  } else if (scenario === 'multi') {
    const r = await c.multi().set('node:t:a', '1').incr('node:t:n').exec();
    console.log('multi', r.length);
  } else if (scenario === 'err') {
    await c.set('node:str', 'v');
    try { await c.lPush('node:str', 'x'); } catch (e) { console.log('error:', e.message); }
    try { await c.sendCommand(['NOSUCHCOMMAND', 'a']); } catch (e) { console.log('error:', e.message); }
  } else {
    console.error('unknown scenario', scenario);
    process.exitCode = 2;
  }
  await c.quit();
}

main().catch((e) => { console.error(e); process.exit(1); });
