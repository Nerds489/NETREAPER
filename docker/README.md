# NETREAPER in a container, and Wi-Fi driver provisioning (#94)

Both optional. `pip install .` on the host stays the baseline (see the top-level
README); this is for a reproducible tool surface and for the injection-capable
Realtek drivers.

## Image

Two stages in [`Dockerfile`](Dockerfile):

| stage | what | size |
|---|---|---|
| `cli` (default) | NETREAPER installed, no security tools | small |
| `full` | `cli` + the arsenal via `bin/netreaper-install essentials` | large |

```bash
# CLI only (planning, dry-run, --help)
docker build -t netreaper:cli -f docker/Dockerfile .
docker run --rm netreaper:cli --version

# With the tools (heavy)
docker build --target full -t netreaper:full -f docker/Dockerfile .
```

The image runs the installed `netreaper` console script as its entrypoint, so
`docker run netreaper:cli <args>` is `netreaper <args>`.

## Running wireless work from the container

Wireless capture and injection need host access the image deliberately does not
bake in (it would stop the image being usable as a plain CLI). Grant it at run
time:

```bash
docker run --rm -it \
  --net=host \
  --cap-add=NET_ADMIN --cap-add=NET_RAW \
  --device=/dev/bus/usb \
  netreaper:full wifi scan wlan0mon
```

The scope gate is unchanged inside the container: deny-by-default, and a
privileged nmap scan still refuses without root (#90). An engagement is still
required for any targeted action.

## Realtek DKMS drivers

[`dkms-drivers.sh`](dkms-drivers.sh) provisions `rtl8812au`, `rtl8814au` and
`rtl8821au` on the **host** (a kernel module cannot live in the container). DKMS
rebuilds them on kernel updates, which is what keeps out-of-tree Realtek drivers
from breaking on every upgrade.

```bash
sudo docker/dkms-drivers.sh
# then reboot and confirm:
dkms status
ip link
```

It takes the Debian/Ubuntu `realtek-rtl88xxau-dkms` shortcut when available
(that one package covers all three chipsets) and otherwise builds each from the
maintained morrownr trees.

> Not verified here: an image build pulls a base and installs packages, and a
> DKMS build needs the running kernel's headers and ideally the adapter, none of
> which the authoring environment has. Build the image and run the script on a
> real host before relying on them.
