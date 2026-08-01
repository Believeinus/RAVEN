// Test classes here run one at a time, not in parallel.
//
// Much of this suite observes the live machine — enumerating every process across four
// kernel interfaces, probing the PID space, reading loaded modules. Those are
// measurements of global state, and running two of them at once means each is measuring
// a machine the other is disturbing.
//
// That is not theoretical. The churn regression test deliberately starts and exits
// hundreds of short-lived processes, and with parallelism on it made a concurrent
// brute-force probe test report four live processes missing from every listing API —
// a false positive inside the test suite, of exactly the kind the product exists to
// avoid. Serial execution costs a few seconds and removes the whole class of problem.

[assembly: CollectionBehavior(DisableTestParallelization = true)]
