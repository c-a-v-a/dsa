{
  description = "A very basic flake";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem
      (system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
          tex = (pkgs.texlive.combine {
            inherit (pkgs.texlive) scheme-small algorithms algorithmicx;
          });
        in
        {
          devShells.default = pkgs.mkShell {
            buildInputs = [
              (pkgs.python3.withPackages (python-pkgs: [
                python-pkgs.pycryptodome
                python-pkgs.sympy
              ]))
              tex
            ];
          };
        }
      );
}
