self:
{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.programs.keyfob;
  keyfobHome = "${config.xdg.configHome}/keyfob";
in
{
  options.programs.keyfob = {
    enable = lib.mkEnableOption "keyfob, Secure Enclave keys unlocked with Touch ID";

    package = lib.mkOption {
      type = lib.types.package;
      default = self.packages.${pkgs.stdenv.hostPlatform.system}.keyfob;
      description = "keyfob package.";
    };

    sshAgent = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = "Run the keyfob SSH agent with launchd and point SSH_AUTH_SOCK at it.";
    };

    git = lib.mkOption {
      type = lib.types.bool;
      default = config.programs.git.enable;
      defaultText = lib.literalExpression "config.programs.git.enable";
      description = ''
        Include keyfob's generated git config (commit signing and credential helper)
        through programs.git. Without programs.git, add
        `[include] path = ~/.config/keyfob/gitconfig` to your git config yourself.
      '';
    };

    sops = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Point SOPS_AGE_KEY_FILE at keyfob's default age key.";
    };
  };

  config = lib.mkIf cfg.enable (
    lib.mkMerge [
      { home.packages = [ cfg.package ]; }

      (lib.mkIf cfg.sshAgent {
        launchd.agents.keyfob = {
          enable = true;
          config = {
            ProgramArguments = [
              "${cfg.package}/bin/keyfob"
              "ssh-agent"
            ];
            EnvironmentVariables.XDG_CONFIG_HOME = config.xdg.configHome;
            RunAtLoad = true;
            KeepAlive = true;
            ProcessType = "Interactive";
            StandardErrorPath = "${config.home.homeDirectory}/Library/Logs/keyfob-agent.log";
          };
        };
        home.sessionVariables.SSH_AUTH_SOCK = "${keyfobHome}/agent.sock";
      })

      (lib.mkIf cfg.git {
        programs.git.includes = [ { path = "${keyfobHome}/gitconfig"; } ];
      })

      (lib.mkIf cfg.sops {
        home.sessionVariables.SOPS_AGE_KEY_FILE = "${keyfobHome}/age/default.txt";
      })
    ]
  );
}
