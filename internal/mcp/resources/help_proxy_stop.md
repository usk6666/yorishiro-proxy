# proxy_stop

Stop the proxy server. Performs a graceful shutdown, waiting for existing connections to complete before stopping.

## Parameters

No parameters required.

## Usage Example

```json
{}
```

## Notes

- The proxy must be running; otherwise an error is returned.
- Active connections are allowed to finish before the server shuts down.
- After stopping, `proxy_start` can be called again to restart.
