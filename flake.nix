{
  outputs =
    { nixpkgs, ... }:
    let
      inherit (builtins) fromTOML readFile mapAttrs;
      project = (fromTOML (readFile ./Cargo.toml)).package;
    in
    {
      packages = mapAttrs (_: pkgs: {
        default = pkgs.rustPlatform.buildRustPackage {
          inherit (project) version;
          pname = project.name;
          cargoLock.lockFile = ./Cargo.lock;
          src = ./.;
        };
      }) nixpkgs.legacyPackages;
    };
}
