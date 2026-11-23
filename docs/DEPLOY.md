# Deploying Cloud Safeguard

Cloud Safeguard is one binary with the console built in. Its state is a SQLite
database and an encryption key in one data directory, so it runs as **exactly
one instance** on a persistent disk. Put HTTPS in front of it and tell it the
public address with `--public-url` (`CSG_PUBLIC_URL` in a container).

Three ways are ready in [`deploy/`](../deploy): Docker (with Caddy for HTTPS),
Kubernetes, and a plain VM such as EC2.

## What to keep safe

- **The master key.** Everything secret in the database (the broker keys of
  your cloud accounts) is encrypted with it. Without it the data cannot be read;
  with it and the database, someone can. Either let `csg init` write
  `master.key` into the data directory (then the backups of that directory are
  as sensitive as your cloud keys), or keep it outside: generate it with
  `head -c 32 /dev/urandom | base64`, store it in your secret manager and pass it
  as `CSG_MASTER_KEY` on every start. Kubernetes below does the latter.
- **The data directory.** Back it up while the service runs (SQLite WAL); a copy
  of `csg.db*` is enough to restore, together with the key.
- **The first setup code.** The first start prints the first supervisor's
  one-time setup code to the log (valid 3 days). Use it at once; if it is lost
  or expired, issue a new one with `csg supervisor recover --username admin`
  (see each section).

## Docker (one host, HTTPS by Caddy)

```bash
docker build -t cloud-safeguard .
export CSG_DOMAIN=csg.example.com            # a DNS record pointing at this host, ports 80/443 open
docker compose -f deploy/docker/compose.yaml up -d
docker compose -f deploy/docker/compose.yaml logs csg    # the setup code
```

Open `https://csg.example.com`, choose *Set up your account* and enter the code.
The container runs read-only, as a non-root user, with all capabilities dropped;
the data lives in the `csg-data` volume. A new setup code:

```bash
docker compose -f deploy/docker/compose.yaml run --rm csg supervisor recover --username admin
```

## Kubernetes (EKS, ACK or any cluster)

1. Push the image to your registry and set it in
   [`statefulset.yaml`](../deploy/k8s/statefulset.yaml).
2. Set your domain in [`configmap.yaml`](../deploy/k8s/configmap.yaml) and
   [`ingress.yaml`](../deploy/k8s/ingress.yaml), and the ingress class and
   certificate source your cluster uses.
3. Create the namespace and the master key, then apply:

```bash
kubectl apply -f deploy/k8s/namespace.yaml
kubectl -n cloud-safeguard create secret generic cloud-safeguard \
  --from-literal=master-key="$(head -c 32 /dev/urandom | base64)"
kubectl apply -k deploy/k8s
kubectl -n cloud-safeguard logs cloud-safeguard-0      # the setup code
```

Keep a copy of the secret's key in your secret manager: deleting the secret
loses access to the data. It is a StatefulSet with one replica and a 1 GiB
volume; do not scale it up. A new setup code:

```bash
kubectl -n cloud-safeguard exec cloud-safeguard-0 -- csg supervisor recover --username admin --data-dir /data
```

## A VM (EC2 or any Linux with systemd)

Build the binary for the VM (`GOOS=linux GOARCH=amd64 make build`, or `arm64`
for Graviton), copy it and [`deploy/ec2/`](../deploy/ec2) to the VM, then as root:

```bash
CSG_DOMAIN=csg.example.com sh deploy/ec2/install.sh ./csg
```

It creates a `csg` system user, initialises `/var/lib/csg` (printing the setup
code), installs the hardened systemd unit (listening on 127.0.0.1:8787 only) and
Caddy for HTTPS. Open ports 80 and 443 in the security group, not 8787. A new
setup code: `sudo -u csg csg supervisor recover --username admin --data-dir /var/lib/csg`.

## After it runs

1. Sign in as the supervisor and add your cloud accounts
   (Cloud accounts → *Add cloud account*; [QUICKSTART](QUICKSTART.md) §2.1–2.9).
2. Add people and give them roles; each signs in and connects their agents
   (`csg login --server https://csg.example.com --name <agent>`).
3. Turn on long-lived keys per account only if you need them (§2.10).

## Checked so far

- Docker image: built, run read-only with all capabilities dropped, initialised
  on the first start, kept its data across a restart, `supervisor recover` and a
  full supervisor setup and sign-in worked.
- Kubernetes manifests: applied on a local kind cluster with the master key from
  a secret; the pod became ready, the service answered, and a deleted pod came
  back with its data and without re-initialising. The ingress was not exercised
  (no ingress controller in kind).
- The VM script and systemd unit: syntax checked only, not yet run on an EC2
  instance.
