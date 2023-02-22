# Bitcoin protocol handshake

## Usage

```bash
cargo run -- --ip 79.189.211.201 --port 8333
```

After executing this command you should see such logs

```
Version message sent
Received command: version
Received command: verack
Handshake complete. Closing connection
```

this means Bitcoin protocol handshake occurred
