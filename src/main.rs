use std::collections::BTreeMap;
use std::str::FromStr;

use bitcoin::consensus::serialize;
use bitcoin::util::sighash::SighashCache;
use bitcoin::{PackedLockTime, PrivateKey};
use bitcoind::bitcoincore_rpc::jsonrpc::base64;
use bitcoind::bitcoincore_rpc::RawTx;
use miniscript::bitcoin::consensus::encode::deserialize;
use miniscript::bitcoin::hashes::hex::FromHex;
use miniscript::bitcoin::util::psbt;
use miniscript::bitcoin::util::psbt::PartiallySignedTransaction as Psbt;
use miniscript::bitcoin::{
    self, secp256k1, Address, Network, OutPoint, Script, Sequence, Transaction, TxIn, TxOut,
};
use miniscript::psbt::{PsbtExt, PsbtInputExt};
use miniscript::Descriptor;
use clap::Parser;

/// Search for a pattern in a file and display the lines that contain it.
#[derive(Parser)]
struct Cli {
    /// The raw transaction we're attempting to spend.
    rawtx: String,
    /// The address we're spending to.
    address: String,
    /// The amount in sats to send to the specified address.
    amount: u64,
    /// The descriptor to sign.
    descriptor: String,
    /// The hot wallet private key.
    hotkey: String,
    /// The cosigner's private key.
    cosigner: String
}

fn main() {
    let args = Cli::parse();

    let secp256k1 = secp256k1::Secp256k1::new();

    let descriptor = Descriptor::from_str(&args.descriptor).unwrap();
    assert!(descriptor.sanity_check().is_ok());
    println!(
        "Descriptor pubkey script: {}",
        descriptor.script_pubkey()
    );
    println!(
        "Descriptor address: {}",
        descriptor.address(Network::Regtest).unwrap()
    );
    println!(
        "Weight for witness satisfaction cost {}",
        descriptor.max_satisfaction_weight().unwrap()
    );

    let hotkey_private =
        PrivateKey::from_str(&args.hotkey).expect("Can't parse the hot wallet private key");

    println!(
        "Hot wallet public key: {}",
        hotkey_private.public_key(&secp256k1)
    );

    let cosigner_private =
        PrivateKey::from_str(&args.cosigner).expect("Can't parse cosigner private key");

    println!(
        "The cosigner public key: {}",
        cosigner_private.public_key(&secp256k1)
    );

    let spend_tx = Transaction {
        version: 2,
        lock_time: PackedLockTime(0),
        input: vec![],
        output: vec![],
    };

    let mut psbt = Psbt {
        unsigned_tx: spend_tx,
        unknown: BTreeMap::new(),
        proprietary: BTreeMap::new(),
        xpub: BTreeMap::new(),
        version: 0,
        inputs: vec![],
        outputs: vec![],
    };

    let depo_tx: Transaction = deserialize(&Vec::<u8>::from_hex(&args.rawtx).unwrap()).unwrap();
    let receiver = Address::from_str(&args.address).unwrap();

    let (outpoint, witness_utxo) = get_vout(&depo_tx, descriptor.script_pubkey());

    let mut txin = TxIn::default();
    txin.previous_output = outpoint;

    txin.sequence = Sequence::MAX;
    psbt.unsigned_tx.input.push(txin);

    psbt.unsigned_tx.output.push(TxOut {
        script_pubkey: receiver.script_pubkey(),
        value: args.amount - 500,
    });

    // Generate signatures & witness data.
    let mut input = psbt::Input::default();
    input
        .update_with_descriptor_unchecked(&descriptor)
        .unwrap();

    input.witness_utxo = Some(witness_utxo.clone());
    psbt.inputs.push(input);
    psbt.outputs.push(psbt::Output::default());

    let mut sighash_cache = SighashCache::new(&psbt.unsigned_tx);

    let msg = psbt
        .sighash_msg(0, &mut sighash_cache, None)
        .unwrap()
        .to_secp_msg();

    // Fixme: Take as parameter.
    let hash_ty = bitcoin::EcdsaSighashType::All;

    let sk1 = hotkey_private.inner;
    let sk2 = cosigner_private.inner;

    // Construct the signatures and add them to the psbt.
    let sig1 = secp256k1.sign_ecdsa(&msg, &sk1);
    let pk1 = hotkey_private.public_key(&secp256k1);
    assert!(secp256k1.verify_ecdsa(&msg, &sig1, &pk1.inner).is_ok());

    let sig2 = secp256k1.sign_ecdsa(&msg, &sk2);
    let pk2 = cosigner_private.public_key(&secp256k1);
    assert!(secp256k1.verify_ecdsa(&msg, &sig2, &pk2.inner).is_ok());

    psbt.inputs[0].partial_sigs.insert(
        pk1,
        bitcoin::EcdsaSig {
            sig: sig1,
            hash_ty: hash_ty,
        },
    );

    psbt.inputs[0].partial_sigs.insert(
        pk2,
        bitcoin::EcdsaSig {
            sig: sig2,
            hash_ty: hash_ty,
        },
    );

    let serialized = serialize(&psbt);
    println!("{}", base64::encode(&serialized));

    psbt.finalize_mut(&secp256k1).unwrap();
    // println!("psbt: {:#?}", psbt);

    let tx = psbt.extract_tx();
    println!("raw: {}", tx.raw_hex());
}

// Find the Outpoint by script pubkey.
fn get_vout(tx: &Transaction, spk: Script) -> (OutPoint, TxOut) {
    for (i, txout) in tx.clone().output.into_iter().enumerate() {
        if spk == txout.script_pubkey {
            return (OutPoint::new(tx.txid(), i as u32), txout);
        }
    }
    panic!("Only call get vout on functions which have the expected outpoint");
}
