# Existing Realtime voice quota enforcement (public-launch blocker)

The direct client Realtime connection uses short-lived credentials and accounting heartbeats. Expiring a credential does not stop a session already started. A client may also open multiple sessions before expiry. Strict provider-side termination and concurrent-session limits require a server-mediated/proxied audio connection or equivalent provider enforcement.

The V16.0.2 text action route uses the existing server usage reservations. It does not change this pre-existing voice transport limitation or claim to close this operational gate.
