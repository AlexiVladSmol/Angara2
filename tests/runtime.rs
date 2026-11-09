//! Runtime contract tests (CPU-01).
//!
//! These tests exercise the public runtime API. Worker counts are asserted
//! through Tokio's public `RuntimeMetrics::num_workers`; no timing or
//! throughput claims are made.

mod common;

use std::future::pending;
use std::time::{Duration, Instant};

use angara::config::{Config, MAX_WORKERS, WorkerThreads};
use angara::runtime::AngaraRuntime;

fn config(workers: &str) -> Config {
    Config::parse(&common::config(workers)).expect("test configuration is valid")
}

#[test]
fn cpu01_fixed_one_worker_executes_tasks_and_shuts_down() {
    let runtime = AngaraRuntime::build(&config("1")).expect("build runtime");
    assert_eq!(runtime.worker_threads(), 1);
    assert_eq!(runtime.metrics_worker_threads(), 1);

    assert_eq!(runtime.block_on(async { 21 * 2 }), 42);

    let task = runtime.spawn(async { 7 });
    assert_eq!(runtime.block_on(task).expect("task completes"), 7);

    runtime.shutdown();
}

#[test]
fn cpu01_fixed_workers_report_requested_count_and_run_concurrent_tasks() {
    let runtime = AngaraRuntime::build(&config("2")).expect("build runtime");
    assert_eq!(runtime.worker_threads(), 2);
    assert_eq!(runtime.metrics_worker_threads(), 2);

    let mut tasks = Vec::new();
    for value in 0..64_u64 {
        tasks.push(runtime.spawn(async move { value * 2 }));
    }

    let sum = runtime.block_on(async move {
        let mut sum = 0_u64;
        for task in tasks {
            sum += task.await.expect("task completes");
        }
        sum
    });

    assert_eq!(sum, (0..64_u64).map(|value| value * 2).sum());
    runtime.shutdown();
}

#[test]
fn cpu01_one_worker_multiplexes_many_tasks() {
    let runtime = AngaraRuntime::build(&config("1")).expect("build runtime");
    assert_eq!(runtime.metrics_worker_threads(), 1);

    let mut tasks = Vec::new();
    for value in 0..256_u64 {
        tasks.push(runtime.spawn(async move {
            tokio::task::yield_now().await;
            value
        }));
    }

    let sum = runtime.block_on(async move {
        let mut sum = 0_u64;
        for task in tasks {
            sum += task.await.expect("task completes");
        }
        sum
    });

    assert_eq!(sum, (0..256_u64).sum::<u64>());
    runtime.shutdown();
}

#[test]
fn cpu01_auto_uses_available_parallelism_within_bounds() {
    let expected = WorkerThreads::Auto.resolve();
    assert!((1..=MAX_WORKERS).contains(&expected));

    let runtime = AngaraRuntime::build(&config("\"auto\"")).expect("build runtime");
    assert_eq!(runtime.worker_threads(), expected);
    assert_eq!(runtime.metrics_worker_threads(), expected);
    assert_eq!(runtime.block_on(async { "ok" }), "ok");
    runtime.shutdown();
}

#[test]
fn cpu01_shutdown_is_bounded_with_pending_tasks() {
    let dir = short_shutdown_config();
    let config = Config::parse(&dir).expect("test configuration is valid");
    let runtime = AngaraRuntime::build(&config).expect("build runtime");

    std::mem::drop(runtime.spawn(pending::<()>()));
    std::mem::drop(runtime.spawn(pending::<()>()));

    let started = Instant::now();
    runtime.shutdown();
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "shutdown took {:?}",
        started.elapsed()
    );
}

#[test]
fn cpu01_drop_performs_bounded_shutdown() {
    let config = Config::parse(&short_shutdown_config()).expect("test configuration is valid");
    let runtime = AngaraRuntime::build(&config).expect("build runtime");
    std::mem::drop(runtime.spawn(pending::<()>()));

    let started = Instant::now();
    drop(runtime);
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "drop took {:?}",
        started.elapsed()
    );
}

fn short_shutdown_config() -> String {
    common::config("\"auto\"").replace("shutdown_timeout_ms = 10000", "shutdown_timeout_ms = 250")
}
