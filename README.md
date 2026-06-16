# AutoRazorpay Go - Fixed Version

## Files
- autorzp.go — Main application (FIXED)
- sites.txt — Razorpay payment page URLs (edit karo)
- px.txt — Proxy list
- go.mod — Go module definition
- live.txt — Auto-generated on run

## Kya fix hua
1. razorpay.me URLs — Ab API se data fetch karta hai (HTML parse broken tha)
2. WAF 403 Block — Tor/bad proxies auto-skip, retry logic added
3. Bad proxy filter — pl-tor, tor., exit. prefix proxies automatically skip

## Run locally
    go run autorzp.go

## Railway deploy
1. Private GitHub repo mein push karo
2. Railway se connect karo
3. Deploy — Go auto-detect hoga

## Endpoint
    GET /razorpay/cc={cc|mm|yy|cvv}
    GET /health
