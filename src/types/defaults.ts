/**
 * Shared deployment defaults, kept in one place so the server, the CLI, the
 * MCP adapter, and the docs cannot drift apart on which port a default
 * store listens on.
 */

/** The port `signet serve` binds when PORT is unset. */
export const DEFAULT_PORT = 8080

/** The store URL every client defaults to when SIGNET_URL is unset. */
export const DEFAULT_URL = 'http://localhost:8080'
