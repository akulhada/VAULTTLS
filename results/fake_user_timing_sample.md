# Fake-user timing study 
Trials per class: 12

## ServerHello length distributions

- wrong password unique lengths: [1431, 1432, 1433]
- unknown user unique lengths: [1431, 1432, 1433]
- length mean (wrong password): 1431.92 bytes, stdev 0.76
- length mean (unknown user): 1432.17 bytes, stdev 0.55

## Failure timing

| Class | Mean | Median | Stdev | P95 |
|---|---:|---:|---:|---:|
| Wrong password | 251.98 ms | 251.78 ms | 4.29 ms | 259.99 ms |
| Unknown user | 252.85 ms | 252.28 ms | 3.76 ms | 258.44 ms |

**Mean timing gap: 0.88 ms**

## Interpretation

The current run shows a very small average timing gap between the wrong-password
and unknown-user paths.

That is encouraging for reduced user-enumeration leakage, but it is still not a
proof of indistinguishability. The study supports the claim that the fake-user
path is close in timing to the wrong-password path in this environment.