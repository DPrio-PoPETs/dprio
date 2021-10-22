extern crate prio;

use prio::client::*;
use prio::encrypt::*;
use prio::field::*;
use prio::server::*;

use dprio::*;

use std::time::Instant;

fn laplace_fixed_params() -> u32 {
    laplace(10000.0_f64, 1.0_f64).unwrap() as u32
}

struct ClientState {
    client: Client<Field32>,
    data: Vec<u32>,
    noise: Vec<u32>,
}

impl ClientState {
    fn new(dimension: usize, public_key1: &PublicKey, public_key2: &PublicKey) -> ClientState {
        ClientState {
            client: Client::new(dimension, public_key1.clone(), public_key2.clone()).unwrap(),
            data: vec![0, 0, 1, 0, 0, 0, 0, 0],
            noise: vec![
                laplace_fixed_params(),
                laplace_fixed_params(),
                laplace_fixed_params(),
                laplace_fixed_params(),
                laplace_fixed_params(),
                laplace_fixed_params(),
                laplace_fixed_params(),
                laplace_fixed_params(),
            ],
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

    fn get_noise(&mut self) -> (Vec<u8>, Vec<u8>) {
        let noise = self
            .noise
            .iter()
            .map(|x| Field32::from(*x))
            .collect::<Vec<Field32>>();
        self.client.encode_simple(&noise).unwrap()
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
        shares: &Vec<Vec<u8>>,
        eval_at: Field32,
    ) -> Vec<VerificationMessage<Field32>> {
        shares
            .iter()
            .map(|share| {
                self.server
                    .generate_verification_message(eval_at, &share)
                    .unwrap()
            })
            .collect()
    }

    fn aggregate(
        &mut self,
        shares: Vec<Vec<u8>>,
        server1_verifications: &Vec<VerificationMessage<Field32>>,
        server2_verifications: &Vec<VerificationMessage<Field32>>,
    ) {
        for ((share, server1_verification), server2_verification) in shares
            .iter()
            .zip(server1_verifications.iter())
            .zip(server2_verifications.iter())
        {
            self.server
                .aggregate(share, server1_verification, server2_verification)
                .unwrap();
        }
    }

    fn total_shares(&self) -> &[Field32] {
        self.server.total_shares()
    }

    fn merge_and_get_total_shares(&mut self, other_server_shares: &[Field32]) -> &[Field32] {
        self.server.merge_total_shares(other_server_shares).unwrap();
        self.total_shares()
    }
}

fn main() {
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

    let dimension = 8;

    let mut server1 = ServerState::new(dimension, true, priv_key1);
    let mut server2 = ServerState::new(dimension, false, priv_key2);

    let n_clients = 10000;
    let mut clients = Vec::with_capacity(n_clients);
    for _ in 0..n_clients {
        clients.push(ClientState::new(
            dimension,
            server1.get_public_key(),
            server2.get_public_key(),
        ));
    }

    let mut shares_for_server1 = Vec::with_capacity(n_clients);
    let mut shares_for_server2 = Vec::with_capacity(n_clients);
    let mut noise_for_server1 = Vec::with_capacity(n_clients);
    let mut noise_for_server2 = Vec::with_capacity(n_clients);
    for mut client in clients {
        let (share1, share2) = client.get_shares();
        shares_for_server1.push(share1);
        shares_for_server2.push(share2);
        let (noise1, noise2) = client.get_noise();
        noise_for_server1.push(noise1);
        noise_for_server2.push(noise2);
    }

    let start_time = Instant::now();
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

    let total_shares = server1.merge_and_get_total_shares(server2.total_shares());
    let elapsed = start_time.elapsed();

    println!(
        "Final Publication: {:?} (in {} ms)",
        total_shares,
        elapsed.as_millis()
    );
}
