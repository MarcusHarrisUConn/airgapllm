# HIPAA Safe Harbor Restricted 3-Digit US ZIP Prefixes (45 CFR 164.514(b)(2))

Returns the 17 three-digit US ZIP code prefixes whose population is
20,000 or fewer under HHS HIPAA Safe Harbor guidance and therefore must
be redacted/zeroed (`000`) even when generalizing geographic data.

## Usage

``` r
hipaa_restricted_zip3()
```

## Value

Character vector of 17 three-digit ZIP prefixes.

## Examples

``` r
hipaa_restricted_zip3()
#>  [1] "036" "059" "063" "102" "203" "556" "692" "790" "821" "823" "830" "831"
#> [13] "878" "879" "884" "890" "893"
```
