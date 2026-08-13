-- Rate cap for the HTTP overhead benchmark (PLAN-HTTP.md М8).
--
-- wrk has no -R of its own (that is wrk2), but it does have `delay()`, which is
-- called before every request on every connection. Pacing each connection by
-- the same amount converges the fleet on a target rate:
--
--     delay_ms = 1000 * connections / target_rps
--
-- A cap is not a detail of the harness, it is the method (Р49): at saturation
-- the load generator and the agent compete for the same cores, so a throughput
-- difference measures the machine's scheduler rather than the agent's cost.
-- Capped below saturation, both sides deliver the same rate and what is left to
-- compare is latency and the agent's own CPU.
local delay_ms = tonumber(os.getenv("WRK_DELAY_MS")) or 0

function delay()
    return delay_ms
end
