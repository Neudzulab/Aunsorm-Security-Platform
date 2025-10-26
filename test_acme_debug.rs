#[cfg(test)]
mod acme_debug {
    use super::*;

    #[test]
    fn test_acme_service_creation() {
        let state = setup_state();
        println!("State created successfully");
        
        let acme_service = state.acme();
        println!("ACME service accessed successfully");
        
        let nonce_url = acme_service.new_nonce_url();
        println!("Nonce URL: {}", nonce_url);
    }
}