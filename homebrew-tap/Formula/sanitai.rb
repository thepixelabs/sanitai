# typed: false
# frozen_string_literal: true

class Sanitai < Formula
  desc "Scan LLM conversation histories for leaked secrets"
  homepage "https://github.com/sanitai/sanitai"
  license "MIT"
  version "0.0.0" # replaced by update-formula.yml on every release

  on_macos do
    on_arm do
      url "https://github.com/sanitai/sanitai/releases/download/v#{version}/sanitai-#{version}-aarch64-apple-darwin.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"
    end
    on_intel do
      url "https://github.com/sanitai/sanitai/releases/download/v#{version}/sanitai-#{version}-x86_64-apple-darwin.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/sanitai/sanitai/releases/download/v#{version}/sanitai-#{version}-aarch64-unknown-linux-musl.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"
    end
    on_intel do
      url "https://github.com/sanitai/sanitai/releases/download/v#{version}/sanitai-#{version}-x86_64-unknown-linux-musl.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"
    end
  end

  def install
    bin.install "sanitai"
  end

  def post_install
    (bash_completion/"sanitai").write \
      Utils.safe_popen_read(bin/"sanitai", "completions", "bash") rescue nil
    (zsh_completion/"_sanitai").write \
      Utils.safe_popen_read(bin/"sanitai", "completions", "zsh") rescue nil
    (fish_completion/"sanitai.fish").write \
      Utils.safe_popen_read(bin/"sanitai", "completions", "fish") rescue nil
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/sanitai --version")
    (testpath/"canary.txt").write("SANITAI_FAKE sk-test-1234567890abcdef1234567890abcdef\n")
    system bin/"sanitai", "scan", "--file", testpath/"canary.txt"
  end
end
