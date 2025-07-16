{
    description = "A basic flake providing a shell with rustup";
    inputs = {
        nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.05";
        flake-utils.url = "github:numtide/flake-utils";
        fenix = {
          url = "github:nix-community/fenix";
          inputs.nixpkgs.follows = "nixpkgs";
        };
    };

    outputs = {self, nixpkgs, flake-utils, fenix}: 
        flake-utils.lib.eachDefaultSystem (system: 
            let 
                overlays = [ fenix.overlays.default ];
                pkgs = import nixpkgs {
                    inherit system overlays;
                };
                rustTc = fenix.packages.${system}.fromToolchainFile { dir = ./.; sha256 = "sha256-Qxt8XAuaUR2OMdKbN4u8dBJOhSHxS+uS06Wl9+flVEk="; };
                in
                {
                    devShells.default = pkgs.mkShell {
                        buildInputs = with pkgs; [
                            binaryen
                            leptosfmt
                            nodejs_22
                            cargo-leptos
                            tailwindcss_4
                            rustTc
                        ];
                    };
                }
        );
}
