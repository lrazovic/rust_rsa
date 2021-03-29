# rust_rsa

A simple, slow, insecure, but (I hope) correct RSA implementation in Rust developed as homework for the Computer and Network Security exam during the MSc in Engineering in Computer Science. 

A naive time comparison between this implementation and OpenSSL is possible with the test 
`RUSTFLAGS="-C target-cpu=native" cargo test --release --package rust_rsa --lib -- check_time_rsa_given_e_versus_real_world --exact --nocapture` 
