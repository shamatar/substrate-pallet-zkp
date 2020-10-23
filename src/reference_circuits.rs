use super::*;
use crate::bellman::SynthesisError;
use crate::bellman::plonk::better_better_cs::cs::*;
use franklin_crypto::plonk::circuit::custom_rescue_gate::Rescue5CustomGate;

// Circuits may have different "geometry" depending on e.g. number of custom
// gates that are used, and whethere lookup tables are used or not.
// "Proof" and "VerificationKey" are generic to have all the data necessary for proof
// in internal format, but they are not aware of particular equations that are required
// for verification. So we provide a basic knowledge about the circuit
// by implementing a part of the Circuit trait to only specify gates used.

// We made a circuit that has only curstom gate for 5th degree non-linearity
// for algebraic hashes like Rescue/Poseidon
#[derive(Clone, Debug)]
pub struct CircuitWithNonlinearityGates;

impl<E: Engine> Circuit<E> for CircuitWithNonlinearityGates {
    type MainGate = Width4MainGateWithDNext;
    fn synthesize<CS: ConstraintSystem<E>>(&self, _cs: &mut CS) -> Result<(), SynthesisError> {
        eprintln!("This is a marker circuit and must not be used for synthesis");
        Err(SynthesisError::Unsatisfiable)
    }
    fn declare_used_gates() -> Result<Vec<Box<dyn GateInternal<E>>>, SynthesisError> {
        Ok(
            vec![
                Self::MainGate::default().into_internal(),
                Rescue5CustomGate::default().into_internal(),
            ]
        )
    }
}

// In addition we specify informaion whether custom gates are used on not
// by extending a trait here to indicate whether lookups are used or not.
// This is not done by default in bellman cause we didn't care about the verifier
// running time, but here we have to make early decisions whether there are additional
// computations necessary or not

pub trait LookupsMarker: Clone + Copy + Send + Sync + std::fmt::Debug {
    fn uses_lookups(&self) -> bool;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CircuitUsesLookups {
    True,
    False
}

impl LookupsMarker for CircuitUsesLookups {
    fn uses_lookups(&self) -> bool {
        match self {
            CircuitUsesLookups::True => true,
            CircuitUsesLookups::False => false,
        }
    }
}

impl From<bool> for CircuitUsesLookups {
    fn from(val: bool) -> Self {
        if val {
            CircuitUsesLookups::True
        } else {
            CircuitUsesLookups::False
        }
    }
}

pub fn validate_vk<E: Engine, C: Circuit<E>>(vk: &VerificationKey<E, C>, marker: CircuitUsesLookups) -> bool {
    // we expect that all extra data entries requried to setup lookup tables
    // are all present or all not present
    let a = vk.total_lookup_entries_length == 0;
    let b = vk.lookup_selector_commitment.is_none();
    let c = vk.lookup_table_type_commitment.is_none();
    let d = vk.lookup_tables_commitments.len() == 0;
    if marker.uses_lookups() {
        // all entries are present
        let valid = !a && !b && !c && !d;

        valid
    } else {
        // all entries are absent
        let valid = a && b && c && d;
        
        valid
    }
}

pub fn validate_proof<E: Engine, C: Circuit<E>>(proof: &Proof<E, C>, marker: CircuitUsesLookups) -> bool {
    let a = proof.lookup_grand_product_commitment.is_none();
    let b = proof.lookup_grand_product_opening_at_z_omega.is_none();
    let c = proof.lookup_s_poly_commitment.is_none();
    let d = proof.lookup_s_poly_opening_at_z_omega.is_none();
    let e = proof.lookup_selector_poly_opening_at_z.is_none();
    let f = proof.lookup_t_poly_opening_at_z.is_none();
    let g = proof.lookup_t_poly_opening_at_z_omega.is_none();
    let h = proof.lookup_table_type_poly_opening_at_z.is_none();
    if marker.uses_lookups() {
        // all entries are present
        let valid = !a && !b && !c && !d && !e && !f && !g && !h;

        valid
    } else {
        // all entries are absent
        let valid = a && b && c && d && e && f && g && h;
        
        valid
    }
}