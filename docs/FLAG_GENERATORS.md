# Flag Generators: Vocabulary + Chaining

A **flag generator** is a runnable workload (currently `docker-compose`) that produces *information/capability* needed to reach the next node(s) in an Attack Flow.

The Flow system treats each generator as a small contract:

- **inputs**: keys the user must already have (from earlier generators)
- **outputs**: keys the generator provides
- **hint_template**: a human-readable hint that tells the user where to go next

## Standard Key Vocabulary

Use these keys consistently so chains can be validated and composed.

### SSH
- `ssh.username`
- `ssh.password`
- `ssh.private_key`

### HTTP / Web
- `http.basic.username`
- `http.basic.password`
- `api.token`

### Progress / Targets
- `next.node_name`
- `next.node_id`
- `flag`

## Hint Templates

Every generator should include a `hint_template`.

Flow will substitute these placeholders (if present):
- `{{THIS_NODE_NAME}}`, `{{THIS_NODE_ID}}`
- `{{NEXT_NODE_NAME}}`, `{{NEXT_NODE_ID}}`
- `{{SCENARIO}}`

Example:

`Next: SSH to {{NEXT_NODE_NAME}} (id={{NEXT_NODE_ID}}) using ssh.username/ssh.password.`

Notes:
- At the moment, Flow provides **node name/id** as the “address-like” hint. If you later want real IPs, we can extend the preview pipeline to compute and expose them.
- For templates that expose files, we recommend including a `hint.txt` in the payload (served over HTTP or mounted into the container) that contains the rendered hint.
