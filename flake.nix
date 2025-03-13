{
  description = "Replit eBPF";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-24.11";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
    let
      pkgs = nixpkgs.legacyPackages.${system};
     in {
        packages.default = pkgs.buildGoModule {
          pname = "replit-ebpf";
          version = "0.0.01";
          src = ./.;
          vendorHash = "sha256-23sMkROWynDN/qvCvSZgXebezg648OY0jsRccxUkq54=";
          buildInputs = [ pkgs.makeWrapper ];

          # integration tests require a local corrupted disk
          doCheck = false;
        };

        devShell = pkgs.mkShell {
          buildInputs = with pkgs; [ go gopls llvm libbpf protobuf protoc-gen-go protoc-gen-go-grpc ];
        };
      });
}
