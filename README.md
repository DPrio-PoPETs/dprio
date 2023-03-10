# DPrio

## Setup

### With Docker

```
$ docker build -t dprio .
$ docker run -i dprio
```

This will build and run a Docker image that runs the `comparison` example,
which simulates and compares Prio to DPrio. NB: running the full simulation may
take several hours. Decrease the number of clients and/or trials to run a
shorter simulation.

### Without Docker

Install rust: https://www.rust-lang.org/tools/install

```
$ cargo run --release --example comparison
```

## Interpreting the output

`comparison` outputs the parameters of each batch of trials with the average
server running time for each of Prio and DPrio, the server overhead, and the
error introduced by DPrio. It then outputs the average client running time for
Prio and DPrio, and the client overhead. After that, for completeness, it
outputs the measurements for each individual simulation.

`comparison` runs three batches of trials: one varying epsilon, one varying the
number of clients, and one varying the number of noises.
