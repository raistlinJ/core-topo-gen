# Restrictions & Limitations

These are general constraints that affect generator authoring and “docker vulnerability target” behavior under CORE.

- **CORE treats docker-compose as a template.** Compose files attached to CORE docker nodes are treated as Mako templates by CORE.
	- Avoid docker-compose env interpolation syntax like `${VAR}` / `${VAR:-default}` in shipped compose templates unless you know it will be resolved before CORE sees it.
	- If you must use interpolation, prefer resolving it on the CORE host *before* node creation.
	- This project resolves/strips `${...}` tokens in generated per-node compose files to avoid CORE Mako failures, but catalog templates should still prefer literal values where possible.

- **Docker nodes run with `network_mode: none`.** This project enforces `network_mode: none` in compose services for CORE docker nodes to prevent Docker from adding an unmanaged default gateway/interface.
	- Consequence: you can’t count on “normal Docker networking” inside the container.
	- Service reachability should be designed around CORE-managed interfaces/IPs.

- **Don’t rely on `ports:` inside CORE.** Published Docker ports (`ports:` / host port mappings) are not a reliable connectivity mechanism *between CORE nodes*.
	- Clients inside CORE should connect to the server using the server node’s CORE IP.
	- If segmentation/firewall rules are enabled, allow the required in-CORE port(s) explicitly.

- **Assume no internet / no package manager at runtime.** Containers may have no outbound access in CORE.
	- Anything required for runtime should be baked into the image (or installed at build time via the iproute2 wrapper flow).
	- Wrapper images default to an offline-safe strategy (inject a BusyBox-backed `ip` implementation). Legacy package-manager installs can be enabled via `CORETG_IPROUTE2_WRAPPER_STRATEGY=packages`.

- **Kernel services may not exist in containers.** Some “system daemons” are kernel-backed (or expect systemd) and won’t work in typical docker-node constraints.
	- Example: an NFS server using kernel `nfsd` usually requires privileged access (mounting `/proc/fs/nfsd`).
	- Prefer a **userspace** server when possible.

- **NFS recommendation (when you need file sharing).** Prefer **NFSv4-only** servers (single TCP/2049) over NFSv3 (rpcbind/mountd/statd + multiple ports).
	- Mounts from other CORE nodes should target `<nfs_node_ip>:/exports` (not `localhost`).
