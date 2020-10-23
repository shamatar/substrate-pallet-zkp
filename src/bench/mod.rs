use frame_support::{assert_ok};
use crate::mock::*;
use crate::tests::*;
use std::time::*;

const LIMIT: u128 = 1_000;

#[test]
#[ignore]
fn custom_benchmark_routine_for_reference_circuit_with_lookups() {
    use sp_core::bytes::from_hex;
    let input = from_hex("0x0d76f22e1d6f4ac0843282b1ea76ceb42450eaae0f88dcb09cb0863613127fb2").unwrap();
    new_test_ext().execute_with(|| {
        // Dispatch a signed extrinsic.
        let start = Instant::now();
        for _ in 0..LIMIT {
            assert_ok!(TemplateModule::verify(Origin::signed(1), input.clone(), VK_BYTES.to_vec(), PROOF_BYTES.to_vec(), true));
        }
        let elapsed = start.elapsed().as_nanos();
        println!("{} ns per verification", elapsed / LIMIT)
    });
}