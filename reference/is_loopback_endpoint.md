# Classify and Validate Whether an Endpoint Is Strictly Local / Loopback

Strictly parses a runtime endpoint URL and verifies that it targets only
the local loopback interface (`127.0.0.1`, `localhost`, or `[::1]`), a
local Unix domain socket (`unix:///...`), or the built-in offline mock
runtime (`mock://offline`). Remote hosts, LAN IP addresses, wildcard
binds (`0.0.0.0`), userinfo spoofing (`http://127.0.0.1@evil.com`), and
unsupported schemes are rejected.

## Usage

``` r
is_loopback_endpoint(endpoint)
```

## Arguments

- endpoint:

  Character scalar URL or an `airgap_runtime` object.

## Value

Logical scalar `TRUE` if the endpoint is strictly local/loopback,
`FALSE` otherwise.

## Examples

``` r
is_loopback_endpoint("http://127.0.0.1:11434")
#> [1] TRUE
is_loopback_endpoint("http://localhost:8000/v1")
#> [1] TRUE
is_loopback_endpoint("https://api.openai.com/v1")
#> [1] FALSE
```
