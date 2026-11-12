# KAFKA v1.0.0

First release of KAFKA, a passive, permission-based website security configuration scanner
for websites you own or are authorized to assess.

## Highlights

* One bounded GET request; five passive modules; HTML, JSON and TXT reports; local history.
* Safety first: explicit authorization, non-public addresses blocked by default, TLS
  verification always on, redirects never followed, strict timeouts and response-size cap,
  cookie values and response bodies never stored.

## Install

Build from source (see `README.md`). The package has not been published to PyPI.

```bash
python -m pip install .
kafka doctor
```

## Known limitations

One endpoint only; header absence is not automatically a vulnerability; CORS review is
limited; technology metadata can be spoofed; HTTPS success is not a TLS audit; DNS validation
has a time-of-check/time-of-use limitation (see `docs/SECURITY.md`). Human review is required.
