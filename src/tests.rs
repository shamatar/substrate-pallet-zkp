use frame_support::{assert_noop, assert_ok};
use frame_support::dispatch::DispatchError;
use crate::mock::*;

pub(crate) static VK_BYTES: &'static [u8] = include_bytes!("../block_vk_17_keccak.key");
pub(crate) static PROOF_BYTES: &'static [u8] = include_bytes!("../block_proof_17_keccak.proof");

#[test]
fn it_works_with_reference_circuit_with_lookups() {
    new_test_ext().execute_with(|| {
        // Dispatch a signed extrinsic.
        assert_ok!(TemplateModule::verify(Origin::signed(1), VK_BYTES.to_vec(), PROOF_BYTES.to_vec(), true));
    });
}

#[test]
fn it_must_not_work_if_we_pretent_to_have_no_lookups() {
    new_test_ext().execute_with(|| {
        // Dispatch a signed extrinsic.
        assert_noop!(TemplateModule::verify(Origin::signed(1), VK_BYTES.to_vec(), PROOF_BYTES.to_vec(), false), DispatchError::Module{index: 0, error:0, message: Some("MalformedVerificationKey")});
    });
}
