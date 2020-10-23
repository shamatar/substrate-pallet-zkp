use frame_support::{assert_noop, assert_ok};
use frame_support::dispatch::DispatchError;
use crate::mock::*;
use sp_core::bytes::from_hex;

pub(crate) static VK_BYTES: &'static [u8] = include_bytes!("../block_vk_17_keccak.key");
pub(crate) static PROOF_BYTES: &'static [u8] = include_bytes!("../block_proof_17_keccak.proof");

#[test]
fn it_works_with_reference_circuit_with_lookups() {
    let input = from_hex("0x0d76f22e1d6f4ac0843282b1ea76ceb42450eaae0f88dcb09cb0863613127fb2").unwrap();
    new_test_ext().execute_with(|| {
        // Dispatch a signed extrinsic.
        assert_ok!(TemplateModule::verify(Origin::signed(1), input, VK_BYTES.to_vec(), PROOF_BYTES.to_vec(), true));
    });
}

#[test]
fn it_must_not_work_if_we_pretent_to_have_no_lookups() {
    let input = from_hex("0x0d76f22e1d6f4ac0843282b1ea76ceb42450eaae0f88dcb09cb0863613127fb2").unwrap();
    new_test_ext().execute_with(|| {
        // Dispatch a signed extrinsic.
        assert_noop!(TemplateModule::verify(Origin::signed(1), input, VK_BYTES.to_vec(), PROOF_BYTES.to_vec(), false), DispatchError::Module{index: 0, error:0, message: Some("MalformedVerificationKey")});
    });
}

#[test]
fn it_must_not_work_if_input_is_not_what_is_in_the_proof() {
    let input = vec![0u8; 32];
    new_test_ext().execute_with(|| {
        // Dispatch a signed extrinsic.
        assert_noop!(TemplateModule::verify(Origin::signed(1), input, VK_BYTES.to_vec(), PROOF_BYTES.to_vec(), true), DispatchError::Module{index: 0, error:1, message: Some("MalformedProof")});
    });
}
