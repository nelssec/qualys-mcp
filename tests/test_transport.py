"""Transport/env configuration tests for HTTP (Streamable HTTP) support."""
import qualys_mcp


def test_transport_defaults_to_stdio():
    assert qualys_mcp._transport_config({}) == ("stdio", "127.0.0.1", 8000, "")


def test_transport_http_env_overrides():
    env = {
        "MCP_TRANSPORT": "HTTP",          # case-insensitive
        "MCP_HOST": "0.0.0.0",
        "MCP_PORT": "9000",
        "MCP_AUTH_TOKEN": "  s3cret  ",   # whitespace stripped
    }
    assert qualys_mcp._transport_config(env) == ("http", "0.0.0.0", 9000, "s3cret")


def test_transport_unknown_value_falls_back_to_stdio_shape():
    # Anything other than "http" behaves as stdio at run time; config just reports it.
    transport, _, _, _ = qualys_mcp._transport_config({"MCP_TRANSPORT": "websocket"})
    assert transport == "websocket"  # main() only branches on == "http"


def test_build_auth_empty_token_disables_auth():
    assert qualys_mcp._build_auth("") is None


def test_build_auth_token_returns_static_verifier():
    from fastmcp.server.auth.providers.jwt import StaticTokenVerifier
    verifier = qualys_mcp._build_auth("tok123")
    assert isinstance(verifier, StaticTokenVerifier)


def test_transport_malformed_port_falls_back():
    transport, host, port, token = qualys_mcp._transport_config({"MCP_PORT": "abc"})
    assert port == 8000
