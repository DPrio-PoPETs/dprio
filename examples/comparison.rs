#[macro_use]
extern crate clap;
extern crate prio;

use clap::Command;
use prio::client::*;
use prio::encrypt::*;
use prio::field::*;
use prio::server::*;
use rand::distributions::Binomial;
use rand::Rng;

use dprio::*;

use std::time::Instant;

struct ClientState {
    client: Client<Field32>,
    data: Vec<u32>,
    noise: Option<Vec<u32>>,
    actual_value: usize,
}

impl ClientState {
    fn new(
        dimension: usize,
        shift_value: isize,
        epsilon: f64,
        generate_noise: bool,
        public_key1: &PublicKey,
        public_key2: &PublicKey,
    ) -> ClientState {
        assert!(dimension > 0);
        assert!(shift_value >= 0);
        let mut data = Vec::with_capacity(dimension);
        // The study is a count, so each client will send either 0 or 1. For this simulation, the
        // probability of sending 1 is 0.5. Since we have to account for negative noise, we also add
        // 2^(dimension - 1) (shift_value) to the value being sent.
        let mut rng = rand::thread_rng();
        let actual_value = rng.sample(Binomial::new(1, 0.5)) as usize;
        let value = shift_value as usize + actual_value;
        for i in 0..dimension {
            let ith_bit = (value >> i) & 1;
            data.push(ith_bit as u32);
        }
        assert!(data.len() == dimension);
        let noise = if generate_noise {
            let mut noise = Vec::with_capacity(dimension);
            let noise_value = laplace::noise(1.0_f64, epsilon).expect("parameters should be fine")
                as isize
                + shift_value;
            assert!(noise_value >= 0);
            for i in 0..dimension {
                let ith_bit = (noise_value >> i) & 1;
                noise.push(ith_bit as u32);
            }
            assert!(noise.len() == dimension);
            Some(noise)
        } else {
            None
        };

        ClientState {
            client: Client::new(dimension, public_key1.clone(), public_key2.clone()).unwrap(),
            data,
            noise,
            actual_value,
        }
    }

    fn get_shares(&mut self) -> (Vec<u8>, Vec<u8>) {
        let data = self
            .data
            .iter()
            .map(|x| Field32::from(*x))
            .collect::<Vec<Field32>>();
        self.client.encode_simple(&data).unwrap()
    }

    fn get_noise(&mut self) -> Option<(Vec<u8>, Vec<u8>)> {
        if let Some(noise) = self.noise.as_ref() {
            let noise = noise
                .iter()
                .map(|x| Field32::from(*x))
                .collect::<Vec<Field32>>();
            Some(self.client.encode_simple(&noise).unwrap())
        } else {
            None
        }
    }
}

struct ServerState {
    server: Server<Field32>,
    public_key: PublicKey,
}

impl ServerState {
    fn new(dimension: usize, is_first_server: bool, private_key: PrivateKey) -> ServerState {
        let public_key = PublicKey::from(&private_key);
        ServerState {
            server: Server::new(dimension, is_first_server, private_key).unwrap(),
            public_key,
        }
    }

    fn get_public_key(&self) -> &PublicKey {
        &self.public_key
    }

    fn generate_verifications(
        &mut self,
        shares: &[Vec<u8>],
        eval_at: Field32,
    ) -> Vec<VerificationMessage<Field32>> {
        shares
            .iter()
            .map(|share| {
                self.server
                    .generate_verification_message(eval_at, share)
                    .unwrap()
            })
            .collect()
    }

    fn aggregate(
        &mut self,
        shares: Vec<Vec<u8>>,
        server1_verifications: &[VerificationMessage<Field32>],
        server2_verifications: &[VerificationMessage<Field32>],
    ) {
        for ((share, server1_verification), server2_verification) in shares
            .iter()
            .zip(server1_verifications.iter())
            .zip(server2_verifications.iter())
        {
            self.server
                .aggregate_by_sum(share, server1_verification, server2_verification)
                .unwrap();
        }
    }

    fn total_sum(&self) -> &Field32 {
        self.server.total_sum()
    }

    fn add_and_get_total_sum(&mut self, other_server_sum: &Field32) -> &Field32 {
        self.server.add_total_shares(other_server_sum);
        self.total_sum()
    }
}

#[derive(Debug)]
struct Results {
    dimension: usize,
    calculated_sum: usize,
    actual_sum: usize,
    client_elapsed: u128,
    server_elapsed: u128,
}

fn main() {
    let matches = Command::new("comparison")
        .version("0.1")
        .author("Dana Keeler <dkeeler@mozilla.com>")
        .about("Compare simulated prio and dprio")
        .arg(arg!(-e --epsilon <VALUE> "value of epsilon for dprio"))
        .arg(arg!(-c --clients <VALUE> "number of clients to simulate"))
        .get_matches();
    let epsilon = matches.value_of("epsilon").unwrap().parse::<f64>().unwrap();
    let n_clients = matches
        .value_of("clients")
        .unwrap()
        .parse::<usize>()
        .unwrap();

    // This code was adapted from
    // https://github.com/abetterinternet/libprio-rs/blob/e58a06de3af0bdcb12e4273751c33b5ceee94d95/examples/sum.rs
    let priv_key1 = PrivateKey::from_base64(
        "BIl6j+J6dYttxALdjISDv6ZI4/VWVEhUzaS05LgrsfswmbLOgN\
         t9HUC2E0w+9RqZx3XMkdEHBHfNuCSMpOwofVSq3TfyKwn0NrftKisKKVSaTOt5seJ67P5QL4hxgPWvxw==",
    )
    .unwrap();
    let priv_key2 = PrivateKey::from_base64(
        "BNNOqoU54GPo+1gTPv+hCgA9U2ZCKd76yOMrWa1xTWgeb4LhF\
         LMQIQoRwDVaW64g/WTdcxT4rDULoycUNFB60LER6hPEHg/ObBnRPV1rwS3nj9Bj0tbjVPPyL9p8QW8B+w==",
    )
    .unwrap();
    let prio_results = do_simulation(
        false,
        epsilon,
        n_clients,
        priv_key1.clone(),
        priv_key2.clone(),
    );
    let dprio_results = do_simulation(
        true,
        epsilon,
        n_clients,
        priv_key1.clone(),
        priv_key2.clone(),
    );
    println!("{:?}", prio_results);
    println!("{:?}", dprio_results);
}

fn do_simulation(
    do_dprio: bool,
    epsilon: f64,
    n_clients: usize,
    priv_key1: PrivateKey,
    priv_key2: PrivateKey,
) -> Results {
    // +1 to minimum bits to be able to handle negative noise values
    let dimension = if do_dprio {
        laplace::min_bits(1.0_f64, epsilon).expect("min_bits should succeed") + 1
    } else {
        1
    };
    let mut server1 = ServerState::new(dimension, true, priv_key1);
    let mut server2 = ServerState::new(dimension, false, priv_key2);

    let shift_value = if do_dprio {
        assert!(dimension > 1 && dimension <= u32::MAX as usize);
        2isize.pow((dimension - 1) as u32)
    } else {
        0
    };
    assert!(shift_value >= 0);
    let mut clients = Vec::with_capacity(n_clients);
    let mut actual_value = 0;
    let client_start_time = Instant::now();
    for _ in 0..n_clients {
        let client = ClientState::new(
            dimension,
            shift_value,
            epsilon,
            do_dprio,
            server1.get_public_key(),
            server2.get_public_key(),
        );
        actual_value += client.actual_value;
        clients.push(client);
    }

    let mut shares_for_server1 = Vec::with_capacity(n_clients);
    let mut shares_for_server2 = Vec::with_capacity(n_clients);
    let mut noise_for_server1 = Vec::with_capacity(n_clients);
    let mut noise_for_server2 = Vec::with_capacity(n_clients);
    for client in &mut clients {
        let (share1, share2) = client.get_shares();
        shares_for_server1.push(share1);
        shares_for_server2.push(share2);
    }
    if do_dprio {
        for mut client in clients {
            let (noise1, noise2) = client.get_noise().unwrap();
            noise_for_server1.push(noise1);
            noise_for_server2.push(noise2);
        }
    }
    let client_elapsed = client_start_time.elapsed();

    let server_start_time = Instant::now();
    if do_dprio {
        let commitment_from_server1 = Commitment::new(n_clients as u64);
        let commitment_from_server2 = Commitment::new(n_clients as u64);
        let closed_commitment_from_server1 = commitment_from_server1.commit();
        let closed_commitment_from_server2 = commitment_from_server2.commit();
        let published_commitment_from_server1 = commitment_from_server1.publish();
        let published_commitment_from_server2 = commitment_from_server2.publish();
        let opened_commitment_from_server1 = closed_commitment_from_server1
            .validate(published_commitment_from_server1)
            .unwrap();
        let opened_commitment_from_server2 = closed_commitment_from_server2
            .validate(published_commitment_from_server2)
            .unwrap();
        let noise_index = OpenedCommitment::gather(&[
            opened_commitment_from_server1,
            opened_commitment_from_server2,
        ])
        .unwrap();
        shares_for_server1.push(noise_for_server1.swap_remove(noise_index as usize));
        shares_for_server2.push(noise_for_server2.swap_remove(noise_index as usize));
    }

    let eval_at = Field32::from(12313);
    let server1_verifications = server1.generate_verifications(&shares_for_server1, eval_at);
    let server2_verifications = server2.generate_verifications(&shares_for_server2, eval_at);

    server1.aggregate(
        shares_for_server1,
        &server1_verifications,
        &server2_verifications,
    );
    server2.aggregate(
        shares_for_server2,
        &server1_verifications,
        &server2_verifications,
    );

    let raw_sum = *server1.add_and_get_total_sum(server2.total_sum());
    let total_shift_count = if do_dprio { n_clients + 1 } else { n_clients };
    let total_shift_value = Field32::from((shift_value as usize * total_shift_count) as u32);
    // assert!(total_shift_value <= raw_sum); TODO: why doesn't this work
    let total_sum = raw_sum - total_shift_value;
    let server_elapsed = server_start_time.elapsed();

    Results {
        dimension,
        calculated_sum: <u32 as From<Field32>>::from(total_sum) as usize,
        actual_sum: actual_value,
        client_elapsed: client_elapsed.as_millis(),
        server_elapsed: server_elapsed.as_millis(),
    }
}
