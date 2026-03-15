# nftui

`nftui` is a modern Terminal User Interface (TUI) for managing `nftables` on Linux. Built with Go and the Bubble Tea framework, it provides a user-friendly way to view, and manage network rulesets.

## Overview

`nftui` aims to simplify the management of `nftables` by providing a high-level, interactive interface. It handles the low-level details of nftables expressions and provides a human-readable representation of rules.

### Key Features
- **Table & Chain Visualization**: Browse your nftables structure easily.
- **Rule Management**: View rules in a human-readable format.
- **TUI Powered**: Responsive and interactive interface using the Bubble Tea framework.
- **Modern Go**: Leverages the latest Go 1.25 idioms for performance and reliability.

## Requirements

- **Go 1.25+**: The project is built using modern Go features.
- **Linux Kernel with nftables support**: Core functionality depends on the `nftables` subsystem.
- **nftables CLI**: The application uses the `nft` command to flush and load initial example rulesets.
- **Capabilities**: Running `nftui` requires `CAP_NET_ADMIN` to interact with the netlink interface.

## Installation & Setup

### Clone the repository
```bash
git clone https://github.com/aafeher/nftui.git
cd nftui
```

### Build the application
```bash
go build -o nftui .
```

### Set necessary capabilities
To run without `sudo`, you can grant the binary the required network administration capabilities:
```bash
sudo setcap cap_net_admin=ep ./nftui
```

## Usage

Start the application by running:
```bash
./nftui
```

*Note: On startup, the application currently attempts to load an example ruleset from `examples/example-nftables-01.conf` using the `nft` CLI.*

### Controls (Bubble Tea Defaults)
- **Arrow Keys / j, k**: Navigate lists and menus.
- **Enter**: Select or enter a view.
- **Esc / q / Ctrl+C**: Go back or exit.

## Project Structure

- `main.go`: Application entry point.
- `nft/`: Core logic for interacting with the `nftables` subsystem.
    - `nft_linux.go`: Linux-specific implementation using `github.com/google/nftables`.
    - `nft_stub.go`: Stub implementation for non-Linux environments.
    - `expr/`: Logic for formatting and serializing various nftables expressions.
    - `nftserializer/`: Higher-level ruleset serialization.
- `ui/`: TUI implementation using `github.com/charmbracelet/bubbletea`.
    - `main_window.go`: Main UI layout and logic.
    - `rule_view.go`, `chain_view.go`: Specialized views for nftables components.
- `examples/`: Sample nftables configuration files.

## Testing

The project includes unit tests for various components, particularly for expression formatting and UI helpers.

Run all tests:
```bash
go test ./...
```

Run specific expression tests:
```bash
go test ./nft/expr/...
```

## TODOs

- [ ] Add support for creating and deleting tables, chains, and rules directly from the TUI.
- [ ] Implement more comprehensive expression support (currently focusing on common types).
- [ ] Improve error handling and reporting for netlink communication.
- [ ] Support for custom configuration file loading via CLI flags.
- [ ] Add more comprehensive integration tests.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.