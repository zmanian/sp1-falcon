//! A simple program that takes a number `n` as input, and writes the `n-1`th and `n`th fibonacci
//! number as an output.

// These two lines are necessary for the program to properly compile.
//
// Under the hood, we wrap your main function with some extra code so that it behaves properly
// inside the zkVM.
#![no_main]
sp1_zkvm::entrypoint!(main);

use alloy_sol_types::SolValue;
use falcon_lib::{verify_signature, PublicValuesStruct};

pub fn main() {
    // Read an input to the program.
    //
    // Behind the scenes, this compiles down to a custom system call which handles reading inputs
    // from the prover.
    let vrfy_key = sp1_zkvm::io::read_vec();

    let signature = sp1_zkvm::io::read_vec();

    let msg = sp1_zkvm::io::read_vec();

    // Compute the n'th fibonacci number using a function from the workspace lib crate.
    let verified = verify_signature(&vrfy_key, &signature, &msg);
    // Encode the public values of the program.
    let public_values = PublicValuesStruct {
        vrfy_key: vrfy_key.into(),
        signature: signature.into(),
        msg: msg.into(),
        verified,
    };

    let bytes = public_values.abi_encode();
    // Commit to the public values of the program. The final proof will have a commitment to all the
    // bytes that were committed to.
    sp1_zkvm::io::commit_slice(&bytes);
}
