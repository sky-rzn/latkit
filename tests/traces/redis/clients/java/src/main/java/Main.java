// Lettuce scenarios (МR0). Defaults only: Lettuce picks its own protocol
// version at connect time, and which one it picks is recon item 2.
import io.lettuce.core.RedisClient;
import io.lettuce.core.RedisURI;
import io.lettuce.core.api.StatefulRedisConnection;
import io.lettuce.core.api.async.RedisAsyncCommands;
import io.lettuce.core.api.sync.RedisCommands;
import io.lettuce.core.protocol.ProtocolVersion;
import io.lettuce.core.ClientOptions;
import io.lettuce.core.RedisFuture;

import java.util.ArrayList;
import java.util.List;

public class Main {
    static String host() {
        String h = System.getenv("REDIS_HOST");
        return h == null ? "127.0.0.1" : h;
    }

    static int port() {
        String p = System.getenv("REDIS_PORT");
        return p == null ? 6399 : Integer.parseInt(p);
    }

    public static void main(String[] args) throws Exception {
        String scenario = args.length > 0 ? args[0] : "basic";
        RedisClient client = RedisClient.create(RedisURI.create(host(), port()));
        if (scenario.equals("resp2")) {
            client.setOptions(ClientOptions.builder()
                    .protocolVersion(ProtocolVersion.RESP2).build());
        }
        try (StatefulRedisConnection<String, String> conn = client.connect()) {
            RedisCommands<String, String> c = conn.sync();
            switch (scenario) {
                case "basic", "resp2" -> {
                    c.set("java:k", "v");
                    System.out.println("get " + c.get("java:k"));
                    c.incr("java:n");
                    c.hset("java:h", "a", "1");
                    System.out.println("hgetall " + c.hgetall("java:h"));
                    c.rpush("java:l", "a", "b", "c");
                    System.out.println("lrange " + c.lrange("java:l", 0, -1));
                    System.out.println("mget " + c.mget("java:k", "java:n", "java:missing"));
                    c.del("java:k", "java:n", "java:h", "java:l");
                }
                case "pipeline" -> {
                    // Lettuce pipelines by flushing manually: 100 commands, one flush.
                    conn.setAutoFlushCommands(false);
                    RedisAsyncCommands<String, String> a = conn.async();
                    List<RedisFuture<String>> fs = new ArrayList<>();
                    for (int i = 0; i < 100; i++) fs.add(a.set("java:p:" + i, "v" + i));
                    conn.flushCommands();
                    for (RedisFuture<String> f : fs) f.get();
                    conn.setAutoFlushCommands(true);
                    System.out.println("pipeline " + fs.size());
                }
                case "multi" -> {
                    c.multi();
                    c.set("java:t:a", "1");
                    c.incr("java:t:n");
                    System.out.println("multi " + c.exec());
                }
                case "block" -> {
                    System.out.println("blpop " + c.blpop(1, "java:bl"));
                }
                case "err" -> {
                    c.set("java:str", "v");
                    try { c.lpush("java:str", "x"); }
                    catch (Exception e) { System.out.println("error: " + e.getMessage()); }
                    try { c.evalsha("f".repeat(40), io.lettuce.core.ScriptOutputType.VALUE); }
                    catch (Exception e) { System.out.println("error: " + e.getMessage()); }
                }
                default -> {
                    System.err.println("unknown scenario " + scenario);
                    System.exit(2);
                }
            }
        } finally {
            client.shutdown();
        }
    }
}
