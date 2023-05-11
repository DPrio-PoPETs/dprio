# DPrio

This repository consists of an implementation of DPrio as well as a small
program to evaluate its performance against Prio.

## Setup

### With Docker

First, ensure Docker is installed and up-to-date (this is out of scope for this
documentation).

To build the Docker image, run `docker build -t dprio .`.

To run the image, run `docker run -i dprio`.

This will build and run a Docker image that runs the `comparison` example,
which simulates and compares Prio to DPrio. By default, the image runs an
abbreviated simulation, as running the full simulation takes several hours.
To run the full simulation, run `docker run -i dprio -- -f`.

### Without Docker

Install rust: https://www.rust-lang.org/tools/install (again, largely out of
scope for this documentation).

To run the abbreviataed simulation, run `cargo run --release --example comparison`.

To run the full simulation, run `cargo run --release --example comparison -- -f`.

## Interpreting the output

`comparison` outputs the parameters of each batch of trials with the average
server running time for each of Prio and DPrio, the server overhead, and the
error introduced by DPrio. It then outputs the average client running time for
Prio and DPrio, and the client overhead.

`comparison` runs three batches of trials: one varying epsilon, one varying the
number of clients, and one varying the number of noises.
