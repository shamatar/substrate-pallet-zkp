#![cfg_attr(not(feature = "std"), no_std)]

use franklin_crypto::bellman;
use franklin_crypto::bellman::pairing;
use franklin_crypto::bellman::pairing::ff;

use crate::ff::{Field, PrimeField, PrimeFieldRepr, ScalarEngine};
use crate::pairing::Engine;
use crate::bellman::plonk::better_better_cs::cs::Circuit;
use crate::bellman::plonk::better_better_cs::proof::Proof;
use crate::bellman::plonk::better_better_cs::setup::VerificationKey;
use crate::bellman::plonk::better_better_cs::verifier::verify;
use crate::bellman::plonk::commitments::transcript::keccak_transcript::RollingKeccakTranscript;
use pairing::bn256::{Bn256, Fr};
use frame_support::{decl_error, decl_module, dispatch};
use frame_support::weights::{DispatchClass, Pays};
// for some magical reason removing this import would make weight function not to compile
#[allow(deprecated)]
use frame_support::weights::FunctionOf;
pub mod reference_circuits;

use self::reference_circuits::{CircuitUsesLookups, validate_proof, validate_vk};

#[cfg(test)]
pub(crate) mod mock;

#[cfg(test)]
pub(crate) mod tests;

#[cfg(test)]
mod bench;

/// Configure the pallet by specifying the parameters and types on which it depends.
pub trait Bn256PlonkVerifier: frame_system::Trait {
    type Circuit: Circuit<Bn256>;
}

// Errors inform users that something went wrong.
decl_error! {
	pub enum Error for Module<T: Bn256PlonkVerifier> {
        MalformedVerificationKey,
        MalformedProof,
		ProofIsInvalid,
	}
}

// Dispatchable functions allows users to interact with the pallet and invoke state changes.
// These functions materialize as "extrinsics", which are often compared to transactions.
// Dispatchable functions must be annotated with a weight and must return a DispatchResult.
decl_module! {
	pub struct Module<T: Bn256PlonkVerifier> for enum Call where origin: T::Origin {
		// Errors must be initialized if they are used by the pallet.
		type Error = Error<T>;

        #[weight = FunctionOf(
 			// weight, function.
            |args: (&Vec<u8>, &Vec<u8>, &Vec<u8>, &bool,)| {
                let mut base = 40_000_000_000; // base 40 ms in WASM, otherwise 8 ms can be used
                if *(args.3) {
                    base += 2_000_000_000; // estra 2ms in WASM, otherwise 0.4 ms can be used
                }

                base
            },
 			// class, fixed.
 			DispatchClass::Operational,
 			// pays fee, function.
 			|_args: (&Vec<u8>, &Vec<u8>, &Vec<u8>, &bool,)| Pays::Yes,
 		)]
		pub fn verify(origin, inputs_encoding: Vec<u8>, key: Vec<u8>, proof: Vec<u8>, uses_lookups_bool: bool) -> dispatch::DispatchResult {
            let uses_lookups = CircuitUsesLookups::from(uses_lookups_bool);
            let vk = Self::parse_vk(&key, uses_lookups).map_err(|_| Error::<T>::MalformedVerificationKey)?;
            let proof = Self::parse_proof(&proof, uses_lookups).map_err(|_| Error::<T>::MalformedProof)?;
            let inputs = Self::parse_inputs(&inputs_encoding).map_err(|_| Error::<T>::MalformedProof)?;
            if inputs.len() != proof.inputs.len() {
                return Err(Error::<T>::MalformedProof)?;
            }
            for (inp, proof_data) in inputs.iter().zip(proof.inputs.iter()) {
                if inp != proof_data {
                    return Err(Error::<T>::MalformedProof)?;
                }
            }
		    let valid = Self::verify_proof(&vk, &proof).map_err(|_| Error::<T>::ProofIsInvalid)?;
		    if valid { Ok(()) } else { Err(Error::<T>::ProofIsInvalid)? }
        }
	}
}

impl<T: Bn256PlonkVerifier> Module<T> {
    const MAX_NUM_INPUTS: usize = 32;
    const FIELD_ELEMENT_ENCODING_SIZE: usize = 32;

    pub fn parse_inputs(encoding: &[u8]) -> Result<Vec< <Bn256 as ScalarEngine>::Fr>, ()> {
        if encoding.len() % Self::FIELD_ELEMENT_ENCODING_SIZE != 0 {
            return Err(());
        }
        let num_inputs = encoding.len() / Self::FIELD_ELEMENT_ENCODING_SIZE;
        if num_inputs > Self::MAX_NUM_INPUTS {
            return Err(());
        }
        let mut inputs = Vec::with_capacity(num_inputs);
        let mut rest = encoding;
        for _ in 0..num_inputs {
            let (this, other) = rest.split_at(Self::FIELD_ELEMENT_ENCODING_SIZE);
            rest = other;
            let fe = Self::parse_field_element(this)?;
            inputs.push(fe);
        }

        Ok(inputs)
    }
    fn parse_field_element(encoding: &[u8]) -> Result< <Bn256 as ScalarEngine>::Fr, ()> {
        assert_eq!(encoding.len(), Self::FIELD_ELEMENT_ENCODING_SIZE);
        let mut repr = <Bn256 as ScalarEngine>::Fr::zero().into_repr();
        repr.read_be(encoding).map_err(|_| ())?;

        <Bn256 as ScalarEngine>::Fr::from_repr(repr).map_err(|_| ())
    }
    pub fn parse_vk(key: &[u8], lookups_marker: CircuitUsesLookups) -> Result<VerificationKey<Bn256, T::Circuit>, ()> {
        let vk: VerificationKey<Bn256, T::Circuit> = VerificationKey::read(key).map_err(|_| ())?;
        let wellformed = validate_vk(&vk, lookups_marker);
        if !wellformed {
            Err(())
        } else {
            Ok(vk)
        }
    }
    pub fn parse_proof(proof: &[u8], lookups_marker: CircuitUsesLookups) -> Result<Proof<Bn256, T::Circuit>, ()> {
        let proof: Proof<Bn256, T::Circuit> = Proof::read(proof).map_err(|_| ())?;
        let wellformed = validate_proof(&proof, lookups_marker);
        if !wellformed {
            Err(())
        } else {
            Ok(proof)
        }
    }
    pub fn verify_proof(vk: &VerificationKey<Bn256, T::Circuit>, proof: &Proof<Bn256, T::Circuit>) -> Result<bool, ()> {
        let valid = verify::<Bn256, T::Circuit, RollingKeccakTranscript<Fr>>(
            &vk,
            &proof,
            None,
        ).map_err(|_| ())?;

        Ok(valid)
    }
}