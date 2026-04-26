use pyo3::prelude::*;

#[pyfunction]
fn verify_zkp() -> PyResult<bool> {
    // Note: Temporary dummy integration test payload
    Ok(zkprust_verifier::validation_engine::ValidationEngine::verify_payload(&[0u8; 64], &[0u8; 32]).is_ok())
}

#[pymodule]
fn gabanode_zkp(_py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(verify_zkp, m)?)?;
    Ok(())
}
