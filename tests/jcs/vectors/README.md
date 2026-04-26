# JCS reference test vectors

These canonical-form JSON files are vendored from
[cyberphone/json-canonicalization](https://github.com/cyberphone/json-canonicalization)
under their original Apache 2.0 license. Source path in the upstream
repo: `testdata/output/`. The cross-language interop check that justifies
the moat thesis (per design doc 3B-A) ports these vectors as compile-
time fixtures.

Test harness: `tests/test_jcs_vectors.c` parameterizes
`jcsp_parse → jcsp_emit → byte-compare` over each file. A successful
round-trip proves our emitter+parser pair agrees with the cyberphone
reference's interpretation of RFC 8785 canonical form.

## Vector status

| File             | Status            | Notes                                   |
|------------------|-------------------|-----------------------------------------|
| `french.json`    | round-trip clean  | object key sort with diacritics         |
| `structures.json`| round-trip clean  | nested objects, arrays, uints, "\n" keys|
| `unicode.json`   | round-trip clean  | UTF-8 string passthrough                |
| `weird.json`     | rejected (known)  | UTF-16 vs UTF-8 sort divergence — see below |

## Vectors NOT vendored

- `arrays.json`, `values.json` — exercise `null`, `true`, `false`, and
  IEEE-754 floats. csh-attest's parser is restricted to objects /
  arrays / strings / unsigned ints (see `jcs_parse.h`); these vectors
  land when v0.x grows the type set.

## Known limitation: UTF-16 vs UTF-8 sort order

RFC 8785 mandates object-key sort by UTF-16 code-unit order. csh-attest
uses byte-wise (UTF-8) comparison via `strcmp` (see `jcs.h`). The two
orderings agree for all ASCII keys and for keys whose codepoints are in
the BMP without crossing the surrogate range — adequate for v1 schema
fields which are ASCII by construction.

`weird.json` exercises a key set spanning both BMP and supplementary
planes (😂 = U+1F602, surrogate pair vs U+FB33 BMP). Under UTF-16 the
surrogate high `D83D` < `FB33`; under UTF-8 the `F0` lead byte > `EF`,
inverting the order. Our sortedness check therefore correctly rejects
this canonical form. The check is asserted as a known-limitation test
in `tests/test_jcs_vectors.c::test_weird_known_limitation`; when v0.x
introduces UTF-16 sort the test flips to expecting round-trip success.

This is a deliberate design choice for v1, not a bug. Documented in the
design doc:

> Sort order is byte-wise — adequate while every v1 schema key is ASCII;
> becomes a UTF-16 conversion at the point a non-ASCII key is introduced.
