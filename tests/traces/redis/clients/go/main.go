// go-redis scenarios (МR0). One scenario per argv[1]; defaults everywhere,
// because the question the corpus asks is what the library does when nobody
// configures it — which protocol it negotiates, how deep it pipelines, whether
// it pools.
package main

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

var ctx = context.Background()

func addr() string {
	h := os.Getenv("REDIS_HOST")
	if h == "" {
		h = "127.0.0.1"
	}
	p := os.Getenv("REDIS_PORT")
	if p == "" {
		p = "6399"
	}
	return h + ":" + p
}

func client(o *redis.Options) *redis.Client {
	if o == nil {
		o = &redis.Options{}
	}
	o.Addr = addr()
	return redis.NewClient(o)
}

func main() {
	scenario := "basic"
	if len(os.Args) > 1 {
		scenario = os.Args[1]
	}
	switch scenario {
	case "basic":
		r := client(nil)
		r.Set(ctx, "go:k", "v", time.Minute)
		fmt.Println(r.Get(ctx, "go:k").Result())
		r.Incr(ctx, "go:n")
		r.HSet(ctx, "go:h", "a", 1, "b", 2)
		fmt.Println(r.HGetAll(ctx, "go:h").Result())
		r.RPush(ctx, "go:l", "a", "b", "c")
		fmt.Println(r.LRange(ctx, "go:l", 0, -1).Result())
		fmt.Println(r.MGet(ctx, "go:k", "go:n", "go:missing").Result())
		r.Del(ctx, "go:k", "go:n", "go:h", "go:l")
	case "pipeline":
		r := client(nil)
		p := r.Pipeline()
		for i := 0; i < 100; i++ {
			p.Set(ctx, fmt.Sprintf("go:p:%d", i), i, time.Minute)
		}
		cmds, _ := p.Exec(ctx)
		fmt.Println("pipeline", len(cmds))
	case "multi":
		r := client(nil)
		p := r.TxPipeline()
		p.Set(ctx, "go:t:a", "1", 0)
		p.Incr(ctx, "go:t:n")
		cmds, _ := p.Exec(ctx)
		fmt.Println("multi", len(cmds))
	case "resp3":
		// go-redis v9 speaks RESP3 by default; Protocol: 2 is the opt-out.
		r := client(&redis.Options{Protocol: 3})
		r.Set(ctx, "go:r3", "v", 0)
		fmt.Println(r.Get(ctx, "go:r3").Result())
		fmt.Println(r.ConfigGet(ctx, "maxmemory").Result())
	case "resp2":
		r := client(&redis.Options{Protocol: 2})
		fmt.Println(r.Ping(ctx).Result())
	case "pool":
		r := client(&redis.Options{PoolSize: 4})
		var wg sync.WaitGroup
		for n := 0; n < 4; n++ {
			wg.Add(1)
			go func(n int) {
				defer wg.Done()
				for i := 0; i < 25; i++ {
					k := fmt.Sprintf("go:pool:%d:%d", n, i)
					r.Set(ctx, k, "x", time.Minute)
					r.Get(ctx, k)
				}
			}(n)
		}
		wg.Wait()
		fmt.Println("pool done")
	case "pubsub":
		r := client(nil)
		sub := r.Subscribe(ctx, "go:chan")
		ch := sub.Channel()
		go func() {
			time.Sleep(300 * time.Millisecond)
			for i := 0; i < 3; i++ {
				client(nil).Publish(ctx, "go:chan", fmt.Sprintf("msg%d", i))
			}
		}()
		got := 0
		for range ch {
			if got++; got >= 3 {
				break
			}
		}
		fmt.Println("received", got)
		sub.Close()
	case "block":
		r := client(nil)
		fmt.Println(r.BLPop(ctx, time.Second, "go:bl").Result())
		go func() {
			time.Sleep(500 * time.Millisecond)
			client(nil).RPush(ctx, "go:bl", "woken")
		}()
		fmt.Println(r.BLPop(ctx, 5*time.Second, "go:bl").Result())
	case "auth":
		r := client(&redis.Options{Username: "lkuser", Password: "lkpass", DB: 3})
		fmt.Println(r.Do(ctx, "ACL", "WHOAMI").Result())
		bad := client(&redis.Options{Username: "lkuser", Password: "nope"})
		fmt.Println(bad.Ping(ctx).Result())
	case "err":
		r := client(nil)
		r.Set(ctx, "go:str", "v", 0)
		fmt.Println(r.LPush(ctx, "go:str", "x").Result())
		fmt.Println(r.EvalSha(ctx, "ffffffffffffffffffffffffffffffffffffffff", nil).Result())
		fmt.Println(r.Do(ctx, "NOSUCHCOMMAND", "a").Result())
	default:
		fmt.Fprintln(os.Stderr, "unknown scenario", scenario)
		os.Exit(2)
	}
}
