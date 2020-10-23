use frame_support::{assert_ok};
use crate::mock::*;
use crate::tests::*;
use std::time::*;

const LIMIT: u128 = 1_000;

#[test]
#[ignore]
fn custom_benchmark_routine_for_reference_circuit_with_lookups() {
    new_test_ext().execute_with(|| {
        // Dispatch a signed extrinsic.
        let start = Instant::now();
        for _ in 0..LIMIT {
            assert_ok!(TemplateModule::verify(Origin::signed(1), VK_BYTES.to_vec(), PROOF_BYTES.to_vec(), true));
        }
        let elapsed = start.elapsed().as_nanos();
        println!("{} ns per verification", elapsed / LIMIT)
    });
}