//! Mirror of Microsoft Nova benchmarks for sequential implementation.
//!
//! Disable default features to run benchmarks in single-threaded mode.
//!
//! Run with `-- --profile-time=*` to enable profiler and generate flamegraphs:
//!     - on linux, you may want to configure `kernel.perf_event_paranoid`.
//!     - currently doesn't work on mac, see https://github.com/tikv/pprof-rs/issues/210.

use std::time::Duration;

use ark_crypto_primitives::sponge::poseidon::PoseidonSponge;

use criterion::*;
use pprof::criterion::{Output, PProfProfiler};

mod shared;
use shared::{NonTrivialTestCircuit, NUM_WARMUP_STEPS};

use nexus_nova::{
    hypernova::sequential::{IVCProof, PublicParams},
    pedersen::PedersenCommitment,
    poseidon_config,
    zeromorph::Zeromorph,
};

type G1 = ark_bn254::g1::Config;
type G2 = ark_grumpkin::GrumpkinConfig;
type C1 = Zeromorph<ark_bn254::Bn254>;
type C2 = PedersenCommitment<ark_grumpkin::Projective>;

type CF = ark_bn254::Fr;

criterion_group! {
    name = recursive_snark;
    config = Criterion::default()
        .with_profiler(PProfProfiler::new(100, Output::Flamegraph(None)))
        .warm_up_time(Duration::from_millis(3000));
    targets = bench_recursive_snark,
}

criterion_main!(recursive_snark);

fn bench_recursive_snark(c: &mut Criterion) {
    let ro_config = poseidon_config();

    // Array of constraints to benchmark
    let constraints = [0, 6399, 22783, 55551, 121087, 252159, 514303, 1038591];
    
    for &num_cons_in_step_circuit in constraints.iter() {
        let mut group = c.benchmark_group(format!(
            "HyperNova-RecursiveSNARK-StepCircuitSize-{num_cons_in_step_circuit}"
        ));
        group.sample_size(10);

        let step_circuit = NonTrivialTestCircuit::new(num_cons_in_step_circuit);

        // Produce public parameters
        let pp = PublicParams::<G1, G2, C1, C2, PoseidonSponge<CF>, NonTrivialTestCircuit<CF>>::test_setup(
            ro_config.clone(),
            &step_circuit,
        ).expect("Failed to set up public parameters");

        // Initialize recursive SNARK
        let mut recursive_snark: IVCProof<G1, G2, C1, C2, PoseidonSponge<CF>, _> =
            IVCProof::new(&[CF::from(2u64)]);

        for i in 0..NUM_WARMUP_STEPS {
            recursive_snark = recursive_snark.prove_step(&pp, &step_circuit)
                .expect("Failed to prove step");

            // Verify the recursive SNARK at each step
            recursive_snark.verify_steps(&pp, i + 1)
                .expect("Verification failed");
        }

        group.bench_function("Prove", |b| {
            b.iter(|| {
                // Produce a recursive SNARK for a step of the recursion
                black_box(recursive_snark.clone())
                    .prove_step(black_box(&pp), black_box(&step_circuit))
                    .expect("Failed to prove step");
            })
        });

        // Benchmark the verification time
        group.bench_function("Verify", |b| {
            b.iter(|| {
                black_box(&recursive_snark)
                    .verify_steps(black_box(&pp), black_box(NUM_WARMUP_STEPS))
                    .expect("Verification failed");
            });
        });

        group.finish();
    }
}
