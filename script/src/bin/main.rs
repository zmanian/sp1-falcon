//! An end-to-end example of using the SP1 SDK to generate a proof of a program that can be executed
//! or have a core proof generated.
//!
//! You can run this script using the following command:
//! ```shell
//! RUST_LOG=info cargo run --release -- --execute
//! ```
//! or
//! ```shell
//! RUST_LOG=info cargo run --release -- --prove
//! ```

use alloy_sol_types::SolType;
use clap::Parser;
use falcon_lib::PublicValuesStruct;
use sp1_sdk::{include_elf, ProverClient, SP1Stdin};
const MESSAGE_TO_SIGN: &[u8] = b"Hello, SP1";

/// The ELF (executable and linkable format) file for the Succinct RISC-V zkVM.
pub const FALCON_ELF: &[u8] = include_elf!("falcon-program");

use fn_dsa::{
    sign_key_size, signature_size, KeyPairGenerator, KeyPairGeneratorStandard, SigningKey,
    SigningKeyStandard, DOMAIN_NONE, FN_DSA_LOGN_512, HASH_ID_RAW,
};
use rand_core::OsRng;

fn generate_keys() -> (Vec<u8>, Vec<u8>) {
    let logn = FN_DSA_LOGN_512;
    // Determine buffer sizes for keys.
    let sign_key_len = sign_key_size(logn);
    // Note: use the vrfy_key_size from our public library (falcon-lib) as it is re-exported
    let vrfy_key_len = fn_dsa::vrfy_key_size(logn);
    let mut sign_key = vec![0u8; sign_key_len];
    let mut vrfy_key = vec![0u8; vrfy_key_len];

    // Generate the key pair.
    let mut kg = KeyPairGeneratorStandard::default();
    kg.keygen(logn, &mut OsRng, &mut sign_key, &mut vrfy_key);
    (sign_key, vrfy_key)
}

fn sign_message(sign_key: &[u8], message: &[u8]) -> Option<Vec<u8>> {
    // Decode the signing key.
    let mut sk = SigningKeyStandard::decode(sign_key).or_else(|| {
        eprintln!("Error: Could not decode signing key");
        None
    })?;
    let logn = sk.get_logn();
    // Allocate buffer for the signature.
    let mut sig = vec![0u8; signature_size(logn)];
    // Produce the signature.
    sk.sign(&mut OsRng, &DOMAIN_NONE, &HASH_ID_RAW, message, &mut sig);
    Some(sig)
}

/// The arguments for the command.
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(long)]
    execute: bool,

    #[clap(long)]
    prove: bool,
}

fn main() {
    // Setup the logger.
    sp1_sdk::utils::setup_logger();
    dotenv::dotenv().ok();

    // Parse the command line arguments.
    let args = Args::parse();

    if args.execute == args.prove {
        eprintln!("Error: You must specify either --execute or --prove");
        std::process::exit(1);
    }

    // Setup the prover client.
    let client = ProverClient::from_env();

    let (signkey, verifykey) = generate_keys();

    let sig = match sign_message(&signkey, MESSAGE_TO_SIGN) {
        Some(sig) => sig,
        None => {
            eprintln!("Signing error");
            std::process::exit(1);
        }
    };

    // Setup the inputs.
    let mut stdin = SP1Stdin::new();
    stdin.write_vec(verifykey);
    stdin.write_vec(sig);
    stdin.write_vec(MESSAGE_TO_SIGN.to_vec());

    if args.execute {
        // // Execute the program
        let (output, report) = client.execute(FALCON_ELF, &stdin).run().unwrap();
        println!("Program executed successfully.");

        // Read the output.
        let decoded = PublicValuesStruct::abi_decode(output.as_slice(), true).unwrap();
        let PublicValuesStruct {
            vrfy_key,
            signature,
            msg,
            verified,
        } = decoded;

        // assert_eq!(verifykey, vrfy_key.to_vec());
        // assert_eq!(sig, signature.to_vec());
        // assert_eq!(MESSAGE_TO_SIGN, msg.to_vec());
        assert!(verified);

        // let (expected_a, expected_b) = fibonacci_lib::fibonacci(n);
        // assert_eq!(a, expected_a);
        // assert_eq!(b, expected_b);
        // println!("Values are correct!");

        // Record the number of cycles executed.
        println!("Number of cycles: {}", report.total_instruction_count());
    } else {
        // Setup the program for proving.
        let (pk, vk) = client.setup(FALCON_ELF);

        // Generate the proof
        let proof = client
            .prove(&pk, &stdin)
            .run()
            .expect("failed to generate proof");

        println!("Successfully generated proof!");

        // Verify the proof.
        client.verify(&proof, &vk).expect("failed to verify proof");
        println!("Successfully verified proof!");
    }
}
