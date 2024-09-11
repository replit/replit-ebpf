{
  description = "Replit eBPF";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-24.05";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
    let
      pkgs = nixpkgs.legacyPackages.${system};
     in {
        packages.default = pkgs.buildGoModule rec {
          pname = "replit-ebpf";
          version = "0.0.01";
          src = ./.;
          vendorHash = "sha256-KWsPgQ2F+m1t4p58GtOGKnc/JBCqkPeMS2YEQmptZb8=";
          buildInputs = [ pkgs.makeWrapper ];
        };

        devShell = pkgs.mkShell {
          buildInputs = with pkgs; [ go gopls llvm libbpf protobuf protoc-gen-go protoc-gen-go-grpc ];
        };
      });
}
