# Request latency (the paper's performance table)

| Comparison | Median | Geom. mean | AF outcome |
| --- | ---: | ---: | --- |
| **Benchmark queries** (119 cases) | | | |
| Native / AF | 1.010 | 1.56 | 58/44/17 W/N/L |
| IndexPriority / AF | 1.068 | 1.69 | 66/29/24 W/N/L |
| IN rewrite / AF | 1.021 | 1.77 | 61/41/17 W/N/L |
| AF / fastest | 1.004 | 1.06 | 50/119 match |
| **Application workload** (50 cases) | | | |
| Native / AF | 5.254 | 11.53 | 38/10/2 W/N/L |
| IndexPriority / AF | 1.009 | 1.91 | 21/19/10 W/N/L |
| IN rewrite / AF | 1.335 | 3.74 | 33/10/7 W/N/L |
| AF / fastest | 1.014 | 1.05 | 19/50 match |

Ratios above one favor the denominator. W/N/L: AF wins, no clear difference, AF losses
(paired 95% intervals over whole measurement cycles). Match: AF's median is the lowest of the
four methods. The benchmark rows omit JOB 14a after the IndexPriority timeout. The planning-cost
row of the paper's table comes from a separate experiment and is not part of these measurements.
