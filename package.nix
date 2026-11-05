{
  lib,
  stdenv,
  swift,
  swiftpm,
  apple-sdk_26,
}:

stdenv.mkDerivation {
  pname = "keyfob";
  version = "0.1.0";

  src = lib.cleanSource ./.;

  nativeBuildInputs = [
    swift
    swiftpm
  ];
  buildInputs = [ apple-sdk_26 ];

  installPhase = ''
    runHook preInstall
    install -Dm755 "$(swiftpmBinPath)/keyfob" $out/bin/keyfob
    # Multicall: git looks for git-credential-<helper>, age for age-plugin-<name>
    ln -s keyfob $out/bin/git-credential-keyfob
    ln -s keyfob $out/bin/age-plugin-se
    runHook postInstall
  '';

  meta = {
    description = "Secure Enclave keys for SSH, git and age, unlocked with Touch ID";
    homepage = "https://github.com/onnimonni/keyfob";
    license = lib.licenses.mit;
    mainProgram = "keyfob";
    platforms = lib.platforms.darwin;
  };
}
