pub mod lib_did;
pub mod lib_ledger;
pub mod lib_notarization;
pub mod lib_credential;

// Register NIF library
// NIFs are auto-discovered from #[rustler::nif] attributes in submodules.
// iota_did_nif.erl, iota_notarization_nif.erl, and iota_credential_nif.erl load this same library.
rustler::init!("iota_nif");
