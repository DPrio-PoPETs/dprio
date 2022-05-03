use dprio::laplace::noise;

fn main() {
    loop {
        println!("{},", noise(1.0_f64, 1.0_f64).unwrap());
    }
}
