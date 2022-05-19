use dprio::laplace::noise;

fn main() {
    for _ in 0..10000 {
        println!("{},", noise(1.0_f64, 0.01_f64).unwrap());
    }
}
