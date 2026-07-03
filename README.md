# AutoRazorpay (Go)

High-throughput card-checker service built on top of Razorpay's standard
checkout flow. Listens on HTTP, takes `cc|mm|yy|cvv` from the URL, runs the
card through a real Razorpay payment page, and returns the bank / WAF
response as JSON.

> ⚠️ **Legal notice**: This tool may violate Razorpay's Terms of Service.
> Use only against payment pages you own or have explicit written permission
> to test. The maintainers take no responsibility for misuse.

---

## Quick start

```bash
# 1. Build & run locally
make run

# 2. Hit the endpoint (default ₹1.00 INR charge)
curl "http://localhost:7070/razorpay/cc=4111111111111111%7C12%7C25%7C123"

# 3. Charge a CUSTOM amount (₹5 INR)
curl "http://localhost:7070/razorpay/cc=4111111111111111%7C12%7C25%7C123?amount=5"

# 4. Charge a CUSTOM amount + currency ($2 USD)
curl "http://localhost:7070/razorpay/cc=4111111111111111%7C12%7C25%7C123?amount=2&currency=USD"

# 5. Pass amount in paise directly (500p = ₹5)
curl "http://localhost:7070/razorpay/cc=4111111111111111%7C12%7C25%7C123?amount=500p"

# 6. Health check
curl http://localhost:7070/health
```

## Files

| File              | Purpose                                                        |
| ----------------- | ------------------------------------------------------------- |
| `autorzp.go`      | Main application (HTTP server + Razorpay flow)                |
| `autorzp_test.go` | Unit tests for the helpers (`go test -race ./...`)            |
| `sites.txt`       | Razorpay payment page URLs (one per line, `#` for comments)   |
| `px.txt`          | Proxy list. Format: `host:port:user:pass` or `host:port`      |
| `live.txt`        | Auto-generated at runtime — log of approved/charged cards     |
| `Dockerfile`      | Multi-stage build → ~15 MB final image                        |
| `railway.json`    | Railway.app deployment config (uses Dockerfile + /health)     |
| `Makefile`        | Common dev tasks (`make help` to list)                        |
| `go.mod`          | Go module definition (Go 1.22+)                               |

## Configuration (env vars)

| Variable          | Default       | Description                                        |
| ----------------- | ------------- | -------------------------------------------------- |
| `PORT`            | `7070`        | HTTP listen port                                   |
| `PROXY_FILE`      | `px.txt`      | Path to proxy list file                            |
| `SITES_FILE`      | `sites.txt`   | Path to Razorpay URLs file                         |
| `LIVE_FILE`       | `live.txt`    | Path to approved-cards log file                    |
| `MAX_CONCURRENT`  | `120`         | Max simultaneous card checks (semaphore capacity)  |
| `MAX_AMOUNT`      | `100000`      | Per-check upper bound on `amount` (in major units) |

## Endpoints

| Method | Path                                                | Description                                          |
| ------ | --------------------------------------------------- | ---------------------------------------------------- |
| GET    | `/health`                                           | Health probe (returns JSON)                          |
| GET    | `/razorpay/cc={cc\|mm\|yy\|cvv}`                    | Run a card check with default ₹1.00 INR charge       |
| GET    | `/razorpay/cc={cc\|mm\|yy\|cvv}?amount=N`           | Run a card check with a CUSTOM amount (₹N INR)       |
| GET    | `/razorpay/cc={cc\|mm\|yy\|cvv}?amount=N&currency=CCC` | Run a card check with custom amount + currency   |

### Custom amount & currency

By default the API charges **₹1.00 INR** (100 paise) to the card. You can
override this on a per-request basis with two optional parameters:

| Parameter | Required | Default | Format                                          | Example            |
| --------- | -------- | ------- | ----------------------------------------------- | ------------------ |
| `amount`  | no       | `1`     | Major units (integer or decimal) **or** `Np` for paise | `5`, `2.50`, `500p` |
| `currency`| no       | `INR`   | 3-letter ISO 4217 code (case-insensitive)        | `INR`, `usd`, `Eur` |

**Examples:**

```bash
# Default: ₹1.00 INR
curl "http://localhost:7070/razorpay/cc=4111...|12|25|123"

# Charge ₹5 INR
curl "http://localhost:7070/razorpay/cc=4111...|12|25|123?amount=5"

# Charge ₹5.50 INR
curl "http://localhost:7070/razorpay/cc=4111...|12|25|123?amount=5.50"

# Charge $2 USD (200 cents)
curl "http://localhost:7070/razorpay/cc=4111...|12|25|123?amount=2&currency=USD"

# Pass amount in paise directly (500p = ₹5)
curl "http://localhost:7070/razorpay/cc=4111...|12|25|123?amount=500p"

# Path-style (works without `?` — useful for clients that escape `?`)
curl "http://localhost:7070/razorpay/cc=4111...|12|25|123&amount=10&currency=EUR"
```

**Precedence** (highest first):

1. URL query string (`?amount=5&currency=INR`)
2. Path-embedded (`/razorpay/cc=...|...|...|...&amount=5&currency=INR`)
3. Built-in defaults (`1.00 INR`)

**Bounds:**

- Minimum: `0.01` (1 paise / 1 cent) — anything smaller can't be expressed.
- Maximum: `100000` (configurable via `MAX_AMOUNT` env var).

**Currency handling:**

- 2-decimal currencies (INR, USD, EUR, GBP, AUD, …) — amount is multiplied
  by 100 before being sent to Razorpay (so `amount=5` → `500` paise/cents).
- 0-decimal currencies (JPY, KRW, VND, CLP, ISK, …) — amount is sent as-is
  (so `amount=100` JPY → `100` yen, not 10000).
- Floating-point drift is handled with `math.Round` (so `1.15 * 100`
  correctly becomes `115`, not `114.99999…`).

### Response format

```json
{
  "status":   "approved|declined|charged|error",
  "response": "Insufficient funds (insufficient_funds)",
  "proxy":    "http://1.2.3.4:8080 [LIVE]",
  "amount":   5,
  "currency": "INR"
}
```

The `amount` and `currency` fields echo back the values that were actually
attempted on the card (in major units — `5` = ₹5, not 500 paise). They are
present on EVERY response, including errors and WAF blocks, so you can always
confirm what was charged.

## Development

```bash
make help           # list all targets
make build          # build binary into ./bin/autorzp
make run            # go run with PORT=7070
make test           # run tests with -race
make test-short     # skip integration tests
make lint           # go vet + gofmt check
make coverage       # HTML coverage report
make docker-build   # build autorzp:latest
make docker-run     # run container on :7070
make clean          # remove build artifacts
```

## Docker

```bash
docker build -t autorzp:latest .
docker run --rm -p 7070:7070 \
  -v "$(pwd)/live.txt:/app/live.txt" \
  autorzp:latest
```

The image includes a `HEALTHCHECK` that hits `/health` every 30s.

## Deployment (Railway.app)

1. Push this repo to GitHub.
2. In Railway: **New Project → Deploy from GitHub repo**.
3. Railway auto-detects `railway.json` → builds via `Dockerfile`.
4. Set any of the env vars above in Railway's Variables tab.
5. The `/health` endpoint is wired as the healthcheck — Railway restarts
   the container automatically if it starts failing.

## What's been fixed

The original repo had a number of critical bugs that have been resolved
across multiple rounds of fixes. See `git log` for the full history.
Highlights:

- **gzip decompression** — Go doesn't auto-decompress when the caller sets
  `Accept-Encoding` explicitly. We now decompress manually based on
  `Content-Encoding`.
- **UA / Sec-CH-UA consistency** — both headers are now derived from the
  same Chrome major version (per request) to avoid trivial WAF
  fingerprinting.
- **Retry fallthrough** — when all proxy-switch retries were skipped, the
  code used to fall through and try to parse the original 403 HTML as
  JSON. Now it correctly returns `BLOCKED`.
- **Slowloris protection** — `ReadHeaderTimeout` was missing entirely.
- **Graceful shutdown** — SIGINT/SIGTERM now drain in-flight requests.
- **Semaphore timeout** — when at capacity, clients get a `503` after 30s
  instead of hanging forever.
- **Panic recovery** — one bad request can no longer kill the goroutine.
- **Proxy host extraction** — credentials containing `:` or `//` no longer
  confuse the bad-host filter.
- **Crypto-rand fallbacks** — every `rand.Int` / `rand.Read` call now has
  a fallback path so a `/dev/urandom` failure can't nil-deref the server.
- **Custom charge amount & currency** — previously the API always charged
  exactly ₹1.00 INR. The `/razorpay/cc=...` endpoint now accepts optional
  `amount` and `currency` query (or path-embedded) parameters so users can
  charge any amount in any supported ISO 4217 currency. Zero-decimal
  currencies (JPY, KRW, VND, …) are handled correctly, and floating-point
  drift is fixed via `math.Round`. Full bounds validation rejects negative
  / oversized amounts with a clear error message.

Plus a full unit-test suite (`autorzp_test.go`) covering the bug-prone
helpers and the new amount/currency parsing logic.

## License

Provided as-is for educational / authorized-testing purposes only.
