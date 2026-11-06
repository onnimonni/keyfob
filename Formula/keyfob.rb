# Homebrew formula, used straight from this repository:
#   brew tap onnimonni/keyfob https://github.com/onnimonni/keyfob
#   brew install keyfob
class Keyfob < Formula
  desc "Secure Enclave keys for SSH, git and age on macOS, unlocked with Touch ID"
  homepage "https://github.com/onnimonni/keyfob"
  url "https://github.com/onnimonni/keyfob/archive/refs/tags/v0.3.1.tar.gz"
  sha256 "ad5f1d9aeefc6c4ec80f502278c7c0a15a54665af4c259596131be9a378193f0"
  license "MIT"
  head "https://github.com/onnimonni/keyfob.git", branch: "main"

  depends_on macos: :tahoe

  # keyfob is a drop-in age-plugin-se (same identities and recipients)
  conflicts_with "age-plugin-se", because: "keyfob installs its own age-plugin-se"

  def install
    system "swift", "build", "--disable-sandbox", "-c", "release"
    bin.install ".build/release/keyfob"
    bin.install_symlink "keyfob" => "git-credential-keyfob"
    bin.install_symlink "keyfob" => "age-plugin-se"
    (lib/"pam").install ".build/release/libpam_keyfob.dylib" => "pam_keyfob.so"
  end

  service do
    run [opt_bin/"keyfob", "ssh-agent"]
    keep_alive true
    process_type :interactive
    error_log_path var/"log/keyfob-agent.log"
  end

  def caveats
    <<~EOS
      Once per user:
        keyfob init                     # keys in this Mac's Secure Enclave
        brew services start keyfob      # the agent, at login
        keyfob install-ssh-config       # plain `ssh` uses the agent
        git config --global include.path ~/.config/keyfob/gitconfig

      sudo with a Touch ID sheet naming the command. sudo runs the module as
      root, so copy it somewhere only root can write (never load it from
      #{HOMEBREW_PREFIX}, which your user can change), again after upgrades:
        sudo install -d -o root -g wheel -m 755 /usr/local/lib/pam
        sudo install -o root -g wheel -m 444 #{opt_lib}/pam/pam_keyfob.so /usr/local/lib/pam/
      then add to the top of /etc/pam.d/sudo_local:
        auth       sufficient     /usr/local/lib/pam/pam_keyfob.so
    EOS
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/keyfob --version")
    assert_match "pam_sm_authenticate", shell_output("nm -gU #{lib}/pam/pam_keyfob.so")
  end
end
