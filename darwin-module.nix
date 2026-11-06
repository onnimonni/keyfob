self:
{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.programs.keyfob;
  sudoLocal = config.security.pam.services.sudo_local;
in
{
  options.programs.keyfob = {
    enable = lib.mkEnableOption "keyfob, Secure Enclave keys unlocked with Touch ID";

    package = lib.mkOption {
      type = lib.types.package;
      default = self.packages.${pkgs.stdenv.hostPlatform.system}.keyfob;
      description = "keyfob package.";
    };

    sudo = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = ''
        Use pam_keyfob for sudo: the Touch ID sheet names the command, its
        directory and the app that asked. Added as `sufficient` before the
        other sudo_local lines (pam_tid, password), so sudo keeps working if it
        is denied or fails.
      '';
    };
  };

  config = lib.mkIf cfg.enable (
    lib.mkMerge [
      { environment.systemPackages = [ cfg.package ]; }

      (lib.mkIf cfg.sudo {
        security.pam.services.sudo_local = {
          enable = true;
          # First, but after pam_reattach so Touch ID also works inside tmux
          text = lib.mkBefore (
            lib.concatLines (
              lib.optional sudoLocal.reattach "auth       optional       ${pkgs.pam-reattach}/lib/pam/pam_reattach.so"
              ++ [ "auth       sufficient     ${cfg.package}/lib/pam/pam_keyfob.so" ]
            )
          );
        };
      })
    ]
  );
}
