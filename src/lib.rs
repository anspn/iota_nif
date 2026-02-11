pub mod lib_did;
pub mod lib_ledger;
pub mod lib_notarization;

// Register NIF library
// NIFs are auto-discovered from #[rustler::nif] attributes in submodules.
// Both iota_did_nif.erl and iota_notarization_nif.erl load this same library.
rustler::init!("iota_nif");
