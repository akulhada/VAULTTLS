# Benchmark Summary 

Configuration:
- iterations: 8
- app rounds: 16
- message size: 1024 bytes

| Metric | Mean | Median | Stdev | P95 |
|---|---:|---:|---:|---:|
| Registration latency | 253.68 ms | 251.56 ms | 6.13 ms | 267.96 ms |
| Login latency | 251.58 ms | 252.54 ms | 4.22 ms | 257.50 ms |
| App round trip | 0.168 ms | 0.159 ms | 0.042 ms | 0.273 ms |
| Throughput | 6.10 MiB/s | 6.14 MiB/s | 1.24 MiB/s | — |


The current measurements suggest a much lower end-to-end cost in this environment,
but they should still be treated as artifact-level measurements rather than as
production benchmark claims.