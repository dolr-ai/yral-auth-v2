{
    description = "A basic flake providing a shell with rustup";
    inputs = {
        nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.05";
        rust-overlay.url = "github:oxalica/rust-overlay";
        flake-utils.url = "github:numtide/flake-utils";
    };

    outputs = {self, nixpkgs, flake-utils, rust-overlay}: 
        flake-utils.lib.eachDefaultSystem (system: 
            let 
                overlays = [ (import rust-overlay) ];
                pkgs = import nixpkgs {
                    inherit system overlays;
                };    
                in
                {
                    devShells.default = pkgs.mkShell {
                        buildInputs = with pkgs; [
                            binaryen
                            leptosfmt
                            nodejs_22
                            cargo-leptos
                            tailwindcss_4
                            (rust-bin.fromRustupToolchainFile ./rust-toolchain.toml)
                        ];
                    };
                }
        );
}
