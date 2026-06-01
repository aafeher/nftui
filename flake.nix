{
  description = "nftui — a Terminal User Interface for Linux nftables";

  # Pinning nixpkgs to a known branch (nixos-unstable for current Go toolchain).
  # Users on stable channels can override with `--override-input nixpkgs ...`.
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    { self
    , nixpkgs
    , flake-utils
    ,
    }:
    # nftui uses Linux netlink syscalls (google/nftables) — Linux-only.
    flake-utils.lib.eachSystem [
      "x86_64-linux"
      "aarch64-linux"
    ]
      (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};

        nftui = pkgs.buildGoModule {
          pname = "nftui";
          # `self.rev` is set on a clean tagged build; falls back to "dirty"
          # for `nix build` against an unclean working tree.
          version =
            if (self ? rev)
            then "0.0.0-${builtins.substring 0 7 self.rev}"
            else "0.0.0-dirty";

          src = ./.;

          # TODO(packager): on the first `nix build` this fakeHash will fail
          # and the error message prints the real `sha256-...` to paste here.
          # Re-pin whenever go.sum changes. The CI release pipeline does not
          # depend on this hash — it's only consumed by Nix users.
          vendorHash = pkgs.lib.fakeHash;

          # buildGoModule defaults to CGO_ENABLED=0, which is what we want —
          # a static binary matching the Goreleaser output. `-s -w` matches
          # the Goreleaser ldflags so the Nix-built binary is the same shape.
          ldflags = [ "-s" "-w" ];

          # Run unit tests as part of the Nix build. Integration tests are
          # excluded by the build tag, so they're naturally skipped here —
          # the sandbox has no netlink anyway.
          doCheck = true;

          # Bundle the man page next to the binary so `man nftui` works
          # after `nix profile install`.
          postInstall = ''
            install -Dm644 man/nftui.1 $out/share/man/man1/nftui.1
          '';

          meta = with pkgs.lib; {
            description = "Terminal User Interface for Linux nftables";
            homepage = "https://github.com/aafeher/nftui";
            changelog = "https://github.com/aafeher/nftui/blob/main/CHANGELOG.md";
            license = licenses.mit;
            mainProgram = "nftui";
            platforms = [ "x86_64-linux" "aarch64-linux" ];
            maintainers = [ ];
          };
        };
      in
      {
        # `nix build` → ./result/bin/nftui
        # `nix build .#nftui` → same
        packages = {
          default = nftui;
          inherit nftui;
        };

        # `nix run` → starts nftui (still needs CAP_NET_ADMIN at runtime;
        # invoke via `sudo $(nix path-info .#default)/bin/nftui` or grant
        # capabilities to the binary).
        apps.default = {
          type = "app";
          program = "${nftui}/bin/nftui";
        };

        # `nix develop` drops you into a shell with the toolchain matching
        # what CI uses: go from go.mod, plus the auxiliary tools the
        # README documents (`goreleaser check`, `mandoc -Tlint`, the live
        # `nft` binary for integration tests).
        devShells.default = pkgs.mkShell {
          packages = with pkgs; [
            go
            gopls
            goreleaser
            nftables
            mandoc
          ];
        };

        # `nix flake check` evaluates this — keeps the package buildable
        # without a separate hydra job.
        checks = {
          inherit nftui;
        };
      });
}
