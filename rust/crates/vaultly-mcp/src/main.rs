use vaultly_mcp::start_mcp_server;

#[tokio::main]
async fn main() {
    start_mcp_server().await;
}