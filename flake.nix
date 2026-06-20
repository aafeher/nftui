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
          # Version derivation: prefer `self.lastModifiedDate` + `self.shortRev`
          # so the Nix store path is at least date-informative
          # (e.g. `nftui-20260601-abc1234`). Dirty trees fall back to a "dirty"
          # suffix so two unclean builds don't accidentally produce
          # collision-free-looking version strings. There is no semver source
          # yet — when the project lands a VERSION file (Post-v0.9.0 roadmap),
          # this block should read from it.
          version =
            let
              date =
                if self ? lastModifiedDate
                then builtins.substring 0 8 self.lastModifiedDate
                else "00000000";
              rev =
                if self ? shortRev
                then self.shortRev
                else "dirty";
            in
            "0-${date}-${rev}";

          src = ./.;

          # Pinned vendor hash for the Go module dependencies. Re-pin whenever
          # go.sum changes: set this back to `pkgs.lib.fakeHash`, run `nix build`
          # (or let the `nix` CI lane in .github/workflows/ci.yml run), and paste
          # the real `sha256-...` the error prints. The CI *release* pipeline does
          # not depend on this hash; only Nix users and the `nix` CI lane use it.
          vendorHash = "sha256-QU6sFQ/6bsgo0YLpo1pVPsQsQTCAfhuyhF7wSi/9GCw=";

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

        # `nix develop` drops you into a shell with the same tool *set* CI
        # uses, plus the auxiliary tools the README documents
        # (`goreleaser check`, `mandoc -Tlint`, the live `nft` binary for
        # integration tests). Note: `pkgs.go` is whatever nixpkgs-unstable
        # currently pins — not necessarily the exact go.mod toolchain
        # version that actions/setup-go resolves in CI.
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
