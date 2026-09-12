class Vaultly < Formula
  desc "Agent-first encrypted credential manager with Cloudflare integration"
  homepage "https://github.com/OWNER/vaultly"
  url "https://github.com/OWNER/vaultly/archive/v#{version}.tar.gz"
  version "1.1.0"
  license "MIT"

  depends_on "rust" => :build

  # The crate is the `vaultly` workspace member under rust/crates/vaultly.
  # std_cargo_args(path:) keeps the formula offline-friendly and free of
  # network fetches at audit time (no vendoring required).
  def install
    system "cargo", "install", *std_cargo_args(path: "rust/crates/vaultly")
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/vaultly version").strip
  end
end
