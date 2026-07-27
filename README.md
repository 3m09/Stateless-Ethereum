# Stateless Ethereum Research Lab

A Python-first research demonstrator for importing real Ethereum account state,
building persisted Merkle Patricia and Verkle trees, and visualizing how
secured account keys are routed through each structure. It can then generate,
verify, benchmark, and persist compatible proofs over those saved trees.

The thesis-level design and proof matrix are described in
[`ARCHITECTURE.md`](ARCHITECTURE.md). This README documents the runnable
software, configuration, data model, tree implementations, storage layout,
API, legacy experiment scripts, and current limitations.

## Project status

| Capability | Status | Notes |
|---|---|---|
| Application foundation | Implemented | FastAPI, Jinja, SQLAlchemy, Alembic, jobs, health checks |
| Ethereum data ingestion | Implemented | Real `eth_getProof` data pinned to an exact block |
| Keccak MPT generation | Implemented | Configurable radix 4–128; radix 16 is Ethereum-compatible |
| Poseidon MPT generation | Implemented | Configurable radix 4–128 over the BN254 scalar field |
| KZG Verkle generation | Implemented | Configurable supported widths over BLS12-381 |
| Tree persistence | Implemented | LevelDB, root reference, JSON manifest, metrics |
| Animated visualization | Implemented | Insertion playback, node inspection, zoom, pan, scrubbing |
| Web prover/verifier runner | Implemented | Supervised MPT and KZG Verkle experiments with persisted results |
| Legacy proof scripts | Available | Separate CLI/configuration path with additional dependencies |

The implemented web workflow is:

```text
Ethereum JSON-RPC
        │
        ▼
Pinned block + eth_getProof account data
        │
        ▼
Dataset: secure keys + account RLP + proof provenance
        │
        ├── Keccak radix-Patricia tree
        ├── Poseidon radix-Patricia tree
        └── KZG Verkle tree
                │
                ▼
LevelDB + root + metrics + manifest + animated topology
                │
                ▼
Compatible prover + verifier + deterministic key sample
                │
                ▼
Verification result + timings + proof size + JSON/CSV artifacts
```

## Main features

- Imports real Ethereum state through a server-side RPC endpoint.
- Resolves `latest`, `safe`, or `finalized` to an exact block number and hash.
- Validates the configured chain ID and detects block changes during an import.
- Supports explicit address lists or recent-transaction-participant sampling.
- Preserves account RLP values and every proof node returned by `eth_getProof`.
- Builds three validated tree profiles from ready datasets.
- Allows users to configure width, key count, and insertion order.
- Persists each generated tree in its own LevelDB directory.
- Records the root, topology, structural metrics, timing, source dataset, and
  public generation parameters.
- Provides a dependency-free animated SVG viewer for MPT and Verkle nodes.
- Resolves a compatible prover, verifier, and setup for each persisted tree.
- Samples proof keys reproducibly using a user-supplied integer seed.
- Measures proof size, proving time, and verification time.
- Persists every proof benchmark in SQLite, JSON, and the legacy CSV shape.
- Keeps RPC credentials and the KZG setup secret out of browser requests and
  tree, proof, and job artifacts.

## Tree profiles

### Valid web profiles

| Profile | `tree_type` | `hash_function` | `setup_type` | Width |
|---|---|---|---|---|
| Keccak MPT | `merkle_patricia` | `keccak` | empty | Any integer from 4 to 128 |
| Poseidon MPT | `poseidon_merkle` | `poseidon` | empty | Any integer from 4 to 128 |
| KZG Verkle | `verkle` | `kzg` | `verkle_kzg` | `16`, `32`, `64`, `128`, `256`, or `512` |

All profiles require 32-byte secured Ethereum account keys. A build may use
between 1 and 2,048 keys, limited further by the number of accounts in its
source dataset.

### MPT width semantics

Ethereum's canonical Merkle Patricia Trie is hexary: each key is routed as
hexadecimal nibbles through a branch with 16 children. Therefore:

- Width 16 uses Ethereum-compatible nibble routing and hex-prefix path encoding.
- Widths 4–128 create experimental generalized radix-Patricia trees.
- Generalized widths are useful for branching-factor and structural benchmarks.
- A generalized-width root is not an Ethereum canonical MPT root.
- The implementation accepts non-power-of-two widths, such as 7 or 100, using
  a fixed-length, collision-free base-N representation of the 32-byte key.

### Implementations selected by the application

The web application and `generate_tree.py` intentionally use these thesis
implementations:

| Profile | Python implementation | Persistence |
|---|---|---|
| Keccak MPT | `tree.merkle_tree.MerklePatriciaTrie` with `hash_fn="keccak"` | `merkle_state_db` |
| Poseidon MPT | `tree.merkle_tree.MerklePatriciaTrie` with `hash_fn="poseidon"` | `merkle_state_db` |
| KZG Verkle | `tree.verkle_tree.VerkleTree` with `VerkleKZGSetup` | `verkle_state_db` |

The older registered `tree.poseidon_merkle_tree.PoseidonMerklePatriciaTrie`
remains in the repository for legacy experiments. The web application does not
use it because it contains historical hard-coded storage locations. The shared
`MerklePatriciaTrie` provides isolated per-build storage for both Keccak and
Poseidon profiles.

`verkle_ipa` is registered as a setup, but the current `VerkleTree` is wired to
KZG commitments. The web app therefore exposes only `verkle_kzg`.

## Web proof profiles

Phase 4 exposes only combinations whose current prover and verifier contracts
have been validated against trees generated by the web application:

| Tree | Prover | Verifier | Setup | Notes |
|---|---|---|---|---|
| Keccak MPT | `merkle` | `merkle` | empty | Complete path per key |
| Keccak MPT | `merkle_optimized` | `merkle_optimized` | empty | Deduplicates shared encoded nodes |
| KZG Verkle | `verkle_multiproof_optimized` | `verkle_multiproof_optimized` | `verkle_kzg` | Aggregated KZG openings and pairing check |

Both MPT profiles support the full configured radix range of 4–128. The
verifier infers the radix from the encoded proof nodes instead of assuming
width 16.

Poseidon/Groth16 is deliberately not presented as runnable. Its legacy PySNARK
prover currently returns placeholder values while its verifier expects
external proof and public-input files, so the two sides do not yet share a
complete proof contract. The FRI/STARK and other historical Verkle variants
remain research implementations; they are not exposed as successful web
profiles until their contracts and security assumptions are validated.

For the optimized KZG Verkle profile, verification is bound to the selected
secure trie keys, their expected Ethereum account RLP values, the persisted
root commitment, and the proof’s aggregated KZG openings and witness.

## Poseidon requirements and behavior

Poseidon tree generation requires:

- The `poseidon-hash` Python package from `requirements.txt`.
- The BN254 scalar field.
- State width 3, 8 full rounds, 57 partial rounds, and an exponent-5 S-box.
- The round constants and MDS matrix exposed by the installed package.
- A 32-byte secured account key and the original Ethereum account RLP value.

Poseidon does **not** require a KZG secret, elliptic-curve ceremony, or
`setup_type`. It replaces Keccak only for node references; the Patricia
leaf/extension/branch structure and LevelDB persistence remain the same.

Width 16 retains the existing fixed, 32-byte-aligned node layout used by the
legacy Groth16 code. Other widths use a versioned variable-length encoding
because branch vectors and paths are no longer fixed at 16 children. Those
generalized Poseidon trees work for generation, storage, lookup, proofs paths,
metrics, and visualization, but the current Groth16 circuit still assumes
width 16.

## KZG Verkle requirements and behavior

The Verkle implementation uses:

- `py-ecc` and the optimized BLS12-381 implementation.
- A KZG structured reference string reconstructed for the selected width.
- Lagrange-basis commitment points for sparse child vectors.
- A server-side positive integer supplied through
  `STATELESS_TREE_SETUP_SECRET`.

The secret is not a user input. The web form and tree API neither accept nor
return it. New tree configurations, job parameters, request artifacts, and
manifests record only that the setup came from the server environment.

The complete account RLP remains in the dataset. For a Verkle commitment, its
integer representation is reduced modulo the BLS12-381 scalar field.

## Technology stack

- Python 3.10+
- FastAPI and Uvicorn
- Jinja2 server-rendered templates
- SQLAlchemy 2 and Alembic
- SQLite by default
- Web3.py and asynchronous HTTP RPC access
- RLP and Keccak/PyCryptodome
- LevelDB through Plyvel
- Poseidon over BN254
- `py-ecc` over BLS12-381
- Plain JavaScript and SVG for visualization

## Repository layout

```text
.
├── app/                         # FastAPI application
│   ├── ethereum/                # RPC client, schemas, import jobs, API/UI
│   ├── trees/                   # Tree schemas, engines, jobs, API/UI
│   ├── proofs/                  # Compatibility, runners, results, API/UI
│   ├── templates/               # Jinja pages and partials
│   └── static/                  # CSS and tree visualization JavaScript
├── merkle/                      # Patricia paths, node encoding, hashing
├── tree/                        # Registered MPT, Poseidon, and Verkle classes
├── verkle/                      # Commitments, serialization, path utilities
├── setups/                      # KZG and IPA setup implementations
├── registry/                    # Tree, setup, prover, and verifier registries
├── prover/ and verifier/        # Legacy proof implementations
├── zkSNARK/ and zkSTARK/        # Legacy proof support code
├── migrations/                  # Alembic schema history
├── tests/                       # Web, ingestion, storage, and tree tests
├── tree_generation_setup.json   # Public defaults for tree generation
├── generate_tree.py             # Legacy standalone tree builder
├── prove_verify.py              # Legacy proof/verification runner
├── requirements.txt             # Canonical application runtime
├── requirements-dev.txt         # Runtime plus test/lint dependencies
└── requirements-research.txt    # Optional legacy proof dependencies
```

## Installation

### System prerequisites

Install Python 3.10 or newer, Git, a compiler toolchain, and LevelDB development
headers. On Debian or Ubuntu:

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-dev build-essential libleveldb-dev
```

Plyvel needs LevelDB headers when a compatible prebuilt wheel is unavailable.

### Python environment

From the repository root:

```bash
python3 -m venv venv
source venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

For development and tests:

```bash
python -m pip install -r requirements-dev.txt
```

For the legacy proof and benchmark scripts:

```bash
python -m pip install -r requirements-research.txt
```

`requirements-research.txt` installs PySNARK from a pinned Git commit and adds
NumPy, Numba, and BLAKE3. Circom, snarkjs, RapidSnark, proving keys, and other
non-Python proof toolchains are separate research prerequisites and are not
installed by pip.

`requirements-web.txt` remains as a compatibility alias for older setup
instructions; it includes the canonical `requirements.txt`.

## Environment configuration

Create a local `.env` file:

```bash
touch .env
```

Add only the settings needed for your environment. For example:

```dotenv
STATELESS_DATABASE_URL=sqlite:///./var/stateless_ethereum.db
STATELESS_ARTIFACT_ROOT=./var/artifacts
STATELESS_AUTO_MIGRATE=true
STATELESS_ETHEREUM_RPC_URL=https://mainnet.infura.io/v3/your-api-key
STATELESS_TREE_SETUP_SECRET=your-positive-integer
```

All application settings use the `STATELESS_` prefix. The RPC URL is required
for Ethereum imports, while the tree setup secret is required only for KZG
Verkle builds.

| Variable | Default | Purpose |
|---|---:|---|
| `STATELESS_APP_NAME` | `Stateless Ethereum Lab` | API and page title |
| `STATELESS_ENVIRONMENT` | `development` | Environment label |
| `STATELESS_DEBUG` | `false` | FastAPI debug behavior |
| `STATELESS_HOST` | `127.0.0.1` | Documented bind host |
| `STATELESS_PORT` | `8000` | Documented bind port |
| `STATELESS_DASHBOARD_JOB_LIMIT` | `25` | Jobs displayed on the dashboard |
| `STATELESS_DATABASE_URL` | `sqlite:///./var/stateless_ethereum.db` | SQLAlchemy database URL |
| `STATELESS_ARTIFACT_ROOT` | `./var/artifacts` | Dataset, tree, and job artifacts |
| `STATELESS_AUTO_MIGRATE` | `true` | Apply Alembic migrations on startup |
| `STATELESS_ETHEREUM_RPC_URL` | unset | Server-side Ethereum JSON-RPC endpoint |
| `STATELESS_ETHEREUM_PROOF_RPC_URL` | data RPC | Optional proof-capable endpoint used for `eth_getProof` |
| `STATELESS_ETHEREUM_NETWORK` | `mainnet` | Stored network label |
| `STATELESS_ETHEREUM_EXPECTED_CHAIN_ID` | `1` | Required RPC chain ID |
| `STATELESS_ETHEREUM_REQUEST_TIMEOUT_SECONDS` | `30` | RPC timeout |
| `STATELESS_ETHEREUM_RETRY_ATTEMPTS` | `3` | RPC retry count |
| `STATELESS_ETHEREUM_RETRY_BACKOFF_SECONDS` | `0.5` | Initial retry backoff |
| `STATELESS_ETHEREUM_PROOF_CONCURRENCY` | `8` | Maximum in-flight proof requests |
| `STATELESS_ETHEREUM_MIN_REQUEST_INTERVAL_SECONDS` | `0` | Delay between starting RPC requests |
| `STATELESS_TREE_SETUP_SECRET` | unset | Server-only KZG setup input |

`STATELESS_HOST` and `STATELESS_PORT` do not configure Uvicorn automatically;
pass the same values to the Uvicorn command when changing the bind address.

### Ethereum RPC

Configure an Infura, Alchemy, local node, or other compatible endpoint:

```bash
STATELESS_ETHEREUM_RPC_URL=https://mainnet.infura.io/v3/your-api-key
STATELESS_ETHEREUM_PROOF_RPC_URL=https://ethereum-rpc.publicnode.com
STATELESS_ETHEREUM_EXPECTED_CHAIN_ID=1
```

The data RPC supplies blocks and transaction participants. The optional proof
RPC supplies `eth_getProof`; separating them is useful when a provider accepts
ordinary calls but returns internal errors for account proofs. Both endpoints
must report the configured chain ID.

Only the provider origin, such as `https://mainnet.infura.io`, is stored with a
dataset. The configured path, query string, and API key are not persisted.

### Verkle setup secret

KZG Verkle builds additionally require:

```bash
STATELESS_TREE_SETUP_SECRET=your-positive-integer
```

Keep the actual value only in `.env`. The file is ignored by Git. Restart the
application after changing `.env`, because settings are loaded and cached when
the process starts.

Older database records or artifacts created before server-only secret handling
was introduced may still contain the former value on disk. Current UI and API
serializers redact it, but historical files are not destructively rewritten.

## Database setup and application startup

Apply migrations explicitly:

```bash
alembic upgrade head
alembic current
```

Start the development server:

```bash
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

When `STATELESS_AUTO_MIGRATE=true`, startup also applies pending migrations.
Explicit migration commands remain recommended when preparing a database.

Open:

- Dashboard: <http://127.0.0.1:8000/>
- Ethereum data: <http://127.0.0.1:8000/data>
- Generated trees: <http://127.0.0.1:8000/trees>
- Proof experiments: <http://127.0.0.1:8000/proofs>
- OpenAPI/Swagger: <http://127.0.0.1:8000/api/docs>
- ReDoc: <http://127.0.0.1:8000/api/redoc>
- Health check: <http://127.0.0.1:8000/healthz>

## End-to-end web workflow

### 1. Import real Ethereum data

Use `/data` to create a dataset. An import can:

- Accept an explicit list of up to 2,048 addresses.
- Scan up to 512 recent blocks for transaction participants.
- Use an exact block number or the `latest`, `safe`, or `finalized` tag.
- Over-collect candidates, retry transient errors, and continue until the
  requested number of successful proofs is reached.
- Require power-of-two account totals: `1`, `2`, `4`, ... `1,024`, or `2,048`.

Example API request:

```bash
curl -X POST http://127.0.0.1:8000/api/v1/ethereum/imports \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "Mainnet account sample",
    "block": "latest",
    "state_mode": "rolling_latest",
    "address_source": "recent_transactions",
    "account_count": 2048,
    "scan_depth": 100
  }'
```

Rolling-latest mode matches `get_eth_data.py`: proofs use the current `latest`
state, and every account stores its derived proof root. Use `pinned` mode with
an archive-capable proof RPC when all accounts must authenticate against one
exact block root.

### Import a local trie JSON dataset

The data page also accepts JSON generated by `get_eth_data.py`:

```json
{
  "0x32-byte-secure-trie-key": "0x-rlp-account-value"
}
```

The top-level object must contain a power-of-two number of entries from 1
through 2,048. Each key must be exactly 32 bytes, and each value must decode as
`RLP([nonce, balance, storageRoot, codeHash])`.

Local imports are validated, normalized, persisted in SQLite, and saved as
dataset artifacts together with the source file SHA-256 digest. This compact
format does not contain original account addresses, block metadata, or
`eth_getProof` paths. Those fields remain unavailable, and the application
does not claim that locally supplied values were independently authenticated.

API clients can upload the same file using multipart form data:

```bash
curl -X POST http://127.0.0.1:8000/api/v1/ethereum/imports/json \
  -F 'name=Local 128-account sample' \
  -F 'data_file=@ethereum_trie_data.json;type=application/json'
```

The `202 Accepted` response contains a dataset and a supervised job. Poll:

```text
GET /api/v1/ethereum/datasets/{dataset_id}
GET /api/v1/ethereum/datasets/{dataset_id}/accounts
GET /api/v1/jobs/{job_id}
```

Each imported account preserves:

- The checksum address.
- `keccak256(address)` as the 32-byte secure trie key.
- `RLP([nonce, balance, storageRoot, codeHash])`.
- Nonce, balance, storage root, and code hash separately.
- Every account-proof node returned by `eth_getProof`.
- The state root derived from each account proof.
- The discovery anchor or pinned block, timestamp, state root, and chain ID.

### 2. Generate a persisted tree

Once a dataset is `ready`, use `/trees` or the tree API.

Keccak MPT example:

```bash
curl -X POST http://127.0.0.1:8000/api/v1/trees/builds \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "Mainnet sample MPT",
    "dataset_id": "your-dataset-uuid",
    "tree_type": "merkle_patricia",
    "hash_function": "keccak",
    "setup_type": "",
    "key_length": 32,
    "width": 16,
    "key_count": 25,
    "insertion_order": "secure_key"
  }'
```

Poseidon MPT example:

```json
{
  "name": "Poseidon radix benchmark",
  "dataset_id": "your-dataset-uuid",
  "tree_type": "poseidon_merkle",
  "hash_function": "poseidon",
  "setup_type": "",
  "key_length": 32,
  "width": 7,
  "key_count": 25,
  "insertion_order": "secure_key"
}
```

KZG Verkle example:

```json
{
  "name": "KZG Verkle benchmark",
  "dataset_id": "your-dataset-uuid",
  "tree_type": "verkle",
  "hash_function": "kzg",
  "setup_type": "verkle_kzg",
  "key_length": 32,
  "width": 256,
  "key_count": 25,
  "insertion_order": "secure_key"
}
```

Do not add a `secret` field. Extra request fields are rejected, and the KZG
secret is read only from the server environment.

The response contains the generated-tree record and its job. Poll:

```text
GET /api/v1/trees/{tree_id}
GET /api/v1/trees/{tree_id}/visualization
GET /api/v1/jobs/{job_id}
```

### 3. Inspect and replay the tree

Open `/trees/{tree_id}` after the build becomes `ready`. The viewer provides:

- Insertion-by-insertion playback.
- A scrubber for selecting an account insertion.
- Branch/extension/leaf rendering for MPTs.
- Internal/suffix rendering for Verkle trees.
- Node hash/reference, depth, path segment, encoding, and encoded size.
- Zoom, pan, reset, and node selection.

Insertion order controls playback, but inserting the same key/value set produces
the same final root for a given validated profile and configuration.

### 4. Prove and verify the tree

Open `/proofs`, choose a ready tree, and select one of the compatible profiles
shown for that tree. Configure the number of keys and a deterministic selection
seed. Poseidon trees remain visible in the tree library, but the proof form
disables submission because their legacy proof contract is incomplete.

Keccak MPT API example:

```bash
curl -X POST http://127.0.0.1:8000/api/v1/proofs/experiments \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "MPT deduplicated benchmark",
    "tree_id": "your-ready-tree-uuid",
    "prover_type": "merkle_optimized",
    "verifier_type": "merkle_optimized",
    "setup_type": "",
    "num_keys_to_prove": 16,
    "selection_seed": 42
  }'
```

KZG Verkle uses:

```json
{
  "name": "KZG Verkle multiproof benchmark",
  "tree_id": "your-ready-verkle-tree-uuid",
  "prover_type": "verkle_multiproof_optimized",
  "verifier_type": "verkle_multiproof_optimized",
  "setup_type": "verkle_kzg",
  "num_keys_to_prove": 8,
  "selection_seed": 42
}
```

The `202 Accepted` response contains the experiment and job. Poll:

```text
GET /api/v1/proofs/experiments/{experiment_id}
GET /api/v1/jobs/{job_id}
```

The requested key count must not exceed the number of keys stored in the tree.
The seed is passed to an isolated deterministic sampler, so repeating the same
tree, count, and seed selects the same account keys.

## Proof defaults and benchmark fields

`proving_setup.json` supplies initial public values for the `/proofs` form:

| JSON key | Web meaning |
|---|---|
| `TREE_ID` | Initially selected tree when that UUID is still ready |
| `PROVER_TYPE` | Initial prover identifier |
| `VERIFIER_TYPE` | Initial verifier identifier |
| `SETUP_TYPE` | Empty for MPT or `verkle_kzg` for Verkle |
| `NUM_KEYS_TO_PROVE` | Initial sample size, capped by the selected tree |

`TREE_TYPE`, `HASH_FN`, and `WIDTH` are not trusted from this file in the web
workflow; they come from the selected persisted tree. The web application also
ignores the legacy `SECRET` field. Verkle always loads
`STATELESS_TREE_SETUP_SECRET` from the server environment.

Each completed run writes the same columns used by the repository’s historical
`results.csv`:

```text
datetime,WIDTH,TREE_TYPE,PROVER_TYPE,VERIFIER_TYPE,SETUP_TYPE,
NUM_KEYS_TO_PROVE,NUM_KEYS_TREE,proof_size,proving_time,verification_time
```

Times are wall-clock seconds and `proof_size` is bytes as calculated by the
selected registered prover. The database additionally records the verification
boolean, sampled keys, selection seed, root, status, error, and artifact path.

## Public tree-generation parameters

`tree_generation_setup.json` contains the public defaults used by `/trees` and
the standalone generator:

```json
{
  "TREE_TYPE": "poseidon_merkle",
  "HASH_FN": "poseidon",
  "SETUP_TYPE": "",
  "KEY_LENGTH": 32,
  "WIDTH": 16,
  "NUM_KEYS": 25
}
```

| Parameter | Meaning |
|---|---|
| `TREE_TYPE` | Tree profile selected by the standalone generator |
| `HASH_FN` | Keccak, Poseidon, or KZG profile hash/commitment |
| `SETUP_TYPE` | Empty for MPT; `verkle_kzg` for Verkle |
| `KEY_LENGTH` | Must be 32 bytes for secured account keys |
| `WIDTH` | Branch/vector width validated for the selected profile |
| `NUM_KEYS` | Number of input key/value pairs to insert |

The KZG setup secret is deliberately absent from this JSON file.

## Standalone tree generator

Run:

```bash
python generate_tree.py
```

The standalone generator:

- Reads public parameters from `tree_generation_setup.json`.
- Reads `data.json` for MPT/Poseidon or `random_data.json` for Verkle.
- Loads the KZG secret from `.env` only when a setup is required.
- Creates `tree_storage/<tree-id>/`.
- Persists LevelDB, the root reference, and `tree_info.json`.
- Appends the generated UUID to `tree_ids.txt`.

Standalone `TREE_TYPE` values use registry names:

| Standalone value | Meaning |
|---|---|
| `merkle` | Shared MPT implementation using the configured hash |
| `poseidon_merkle` | Shared MPT implementation forced to Poseidon |
| `verkle` | Registered KZG Verkle implementation |

The standalone input files are repository fixtures. For new real Ethereum
imports and reproducible provenance, prefer the web workflow.

## Legacy proof and benchmark scripts

The repository retains the original research runners:

- `prove_verify.py` reads `proving_setup.json`, reloads a generated tree,
  samples keys, generates a proof, verifies it, and appends metrics to
  `results.csv`.
- `automate_prove_verify.py` repeats `prove_verify.py` for tree IDs and key
  counts in `automate_prove_verify_input.json`.
- `run_experiment.py` builds and benchmarks combinations from
  `experiment.json`.

These scripts predate the server-only web configuration and have independent
toolchain assumptions. Some legacy JSON files still contain setup values. Do
not serve those files publicly. The web form reads only the allow-listed public
defaults described above and never reads or exposes `SECRET`.

Proof families represented in the registries include:

- Standard and deduplicated Merkle proofs.
- Standard, optimized, and multiproof Verkle variants.
- Poseidon/Groth16 research code.
- FRI-based STARK research code.

The broader research matrix is in [`ARCHITECTURE.md`](ARCHITECTURE.md). The
validated subset in the web proof profile table is supervised by the web job
system; the other registry entries remain legacy research code.

## Persistence and artifacts

### Database

The default database is:

```text
var/stateless_ethereum.db
```

It stores:

- Jobs and status transitions.
- Ethereum datasets.
- Imported Ethereum accounts and proof nodes.
- Generated-tree identities, public configurations, roots, metrics, timing,
  status, and artifact paths.
- Proof experiment configuration, deterministic sample, verification result,
  size, proving/verification timing, status, and artifact path.

### Dataset artifacts

```text
var/artifacts/datasets/<dataset-id>/
├── request.json
└── snapshot.json
```

`request.json` records the public import request. `snapshot.json` binds all
account values and proof paths to the pinned block.

### Tree artifacts

```text
var/artifacts/trees/<tree-id>/
├── request.json
├── manifest.json
├── visualization.json
└── storage/
    ├── root.bin
    ├── merkle_root_ref.bin      # MPT/Poseidon only
    ├── verkle_root_ref.bin      # Verkle only
    ├── merkle_state_db/         # MPT/Poseidon only
    └── verkle_state_db/         # Verkle only
```

Only the files relevant to the selected profile are created.

- `root.bin` contains the normalized experimental root reference.
- The profile-specific root file is maintained by the thesis tree class.
- LevelDB contains the encoded nodes addressed by hash or commitment reference.
- `manifest.json` binds the root, metrics, timing, public configuration, source
  dataset, and pinned block.
- `visualization.json` contains the final topology and insertion routes used by
  the SVG viewer.

Job lifecycle manifests are stored under:

```text
var/artifacts/jobs/<job-id>/manifest.json
```

### Proof artifacts

```text
var/artifacts/proofs/
├── results.csv                         # Cumulative web benchmark rows
└── <experiment-id>/
    ├── request.json                    # Public request + resolved profile
    ├── result.json                     # Verification result and metrics
    ├── result.csv                      # One row in legacy results.csv shape
    └── sampled_keys.json               # Seed, addresses, and secure keys
```

The root-level historical `results.csv` is not mutated by the web application.
It remains available to the standalone scripts. Phase 4 appends its cumulative
web results under the artifact root instead.

## Root and data interpretation

Every tree uses the already-secured key imported with the account:

```text
key = keccak256(20-byte account address)
```

The tree builders do not hash that key a second time.

For MPT and Poseidon MPT, the value is the exact account RLP:

```text
RLP([nonce, balance, storageRoot, codeHash])
```

For Verkle, the original RLP remains in the dataset, while the committed scalar
is its integer value modulo the BLS12-381 scalar field.

A generated tree covers only the selected sample. Its experimental root must
not be compared to the canonical state root of the complete Ethereum block.
The source block's canonical root is retained as provenance, not as an expected
generated-tree result.

## API summary

| Method | Endpoint | Purpose |
|---|---|---|
| `GET` | `/healthz` | Database/artifact health |
| `POST` | `/api/v1/ethereum/imports` | Queue a real Ethereum import |
| `GET` | `/api/v1/ethereum/datasets` | List datasets |
| `GET` | `/api/v1/ethereum/datasets/{id}` | Inspect dataset status |
| `GET` | `/api/v1/ethereum/datasets/{id}/accounts` | List imported accounts |
| `POST` | `/api/v1/trees/builds` | Queue a tree build |
| `GET` | `/api/v1/trees` | List generated trees |
| `GET` | `/api/v1/trees/{id}` | Inspect tree status and metrics |
| `GET` | `/api/v1/trees/{id}/visualization` | Read visualization data |
| `GET` | `/api/v1/proofs/profiles` | List runnable proof contracts |
| `POST` | `/api/v1/proofs/experiments` | Queue proving and verification |
| `GET` | `/api/v1/proofs/experiments` | List proof benchmarks |
| `GET` | `/api/v1/proofs/experiments/{id}` | Inspect proof status and results |
| `GET` | `/api/v1/jobs` | List jobs |
| `GET` | `/api/v1/jobs/{id}` | Inspect a job |

The interactive OpenAPI documentation at `/api/docs` is authoritative for
request and response schemas.

## Tests and validation

Run the full test suite:

```bash
pytest
```

Run lint and syntax checks:

```bash
ruff check app tests
python -m py_compile app/trees/engine.py tree/merkle_tree.py generate_tree.py
node --check app/static/app.js
node --check app/static/tree-viz.js
```

Check dependency consistency and migration state:

```bash
python -m pip check
alembic current
```

The tests cover application health, job transitions, guarded artifact paths,
RPC configuration and retries, reproducible Ethereum imports, MPT generation,
non-power-of-two Poseidon routing, MPT boundary widths, KZG Verkle generation,
standard and deduplicated generalized-radix MPT proofs, KZG multiproof
verification, incompatible Poseidon rejection, CSV result persistence, secret
redaction, manifests, and visualization data.

## Operational limitations

- Import and tree jobs run as in-process asynchronous tasks. Proof experiments
  run in a single supervised worker thread so pairing work does not block HTTP.
- Run one Uvicorn worker so jobs are not split across independent process
  memory. A durable external queue is planned.
- The demonstrator imports and builds trees from at most 2,048 accounts per
  dataset. RPC quotas and proof latency determine total collection time.
- KZG setup generation can be expensive at larger widths. Setup objects are
  cached per process by secret and width.
- Width 16 is required for the current Poseidon Groth16 circuit.
- Only KZG, not IPA, is connected to the current Verkle tree.
- The web runner intentionally excludes incomplete Poseidon/Groth16, STARK, and
  mismatched legacy Verkle proof contracts.
- SQLite is the supported default. SQLAlchemy models are portable, but another
  database also requires an appropriate driver and deployment testing.
- Historical legacy scripts and artifacts do not automatically inherit the
  web application's secret-handling policy.

## Troubleshooting

### `STATELESS_ETHEREUM_RPC_URL is not configured`

Set the endpoint in `.env` and restart Uvicorn.

### RPC `-32603 Internal error` during `eth_getProof`

Configure a proof-capable endpoint separately:

```dotenv
STATELESS_ETHEREUM_PROOF_RPC_URL=https://ethereum-rpc.publicnode.com
STATELESS_ETHEREUM_PROOF_CONCURRENCY=8
STATELESS_ETHEREUM_MIN_REQUEST_INTERVAL_SECONDS=0
```

The importer retries transient errors, skips candidates that remain
unavailable, and over-collects addresses to reach the requested success count.

### `STATELESS_TREE_SETUP_SECRET is required for Verkle builds`

Set a positive integer in `.env` and restart the application. MPT and Poseidon
builds do not need this setting.

### Plyvel or LevelDB installation fails

Install the LevelDB development package and compiler toolchain, then reinstall
`requirements.txt`.

### A tree request returns `422`

Check the exact tree/hash/setup/width combinations in the profile table. The
API rejects incompatible profiles and unexpected fields.

### The generated root differs from the Ethereum block state root

This is expected. The generated root covers only the sampled accounts and may
also use a different radix, hash, or commitment scheme.

### `.env` changes do not take effect

Restart the process. Application settings and KZG setup objects are cached.
