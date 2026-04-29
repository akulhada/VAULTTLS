# Sample codec fuzzing summary

Iterations per decoder: 1000  
Seed: 539

| Decoder | Accepted | AssertionError | ValueError | Unexpected |
|---|---:|---:|---:|---:|
| decode_client_hello | 275 | 492 | 233 | 0 |
| decode_server_hello | 233 | 527 | 240 | 0 |
| decode_client_finish | 232 | 537 | 231 | 0 |
| decode_app_data | 258 | 496 | 246 | 0 |
| decode_alert | 229 | 531 | 240 | 0 |

## Interpretation

The qualitative outcome is unchanged from the earlier fuzzing sample:

- the decoders reject many random inputs cleanly with `AssertionError` or `ValueError`
- some random inputs are accepted because they accidentally satisfy the grammar
- there were **no unexpected exceptions**

Accepted malformed inputs are not automatically bugs; some random byte strings can
still satisfy the message format by chance.