package main

import (
	"fmt"
	"log"
	"nftui/nft"
	"nftui/ui"
	"os"

	tea "github.com/charmbracelet/bubbletea"
)

func main() {
	err := nft.LoadExamples()
	if err != nil {
		log.Fatalf("Hiba: %v", err)
	}

	//p := tea.NewProgram(ui.InitialMainWindow(), tea.WithAltScreen())
	p := tea.NewProgram(ui.InitialMainWindow())
	if _, err := p.Run(); err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}
}
