use dprio::laplace::noise;

fn main() {
    for _ in 0..10000 {
        println!("{},", noise(0.5_f64, 1.0_f64).unwrap());
    }
}
