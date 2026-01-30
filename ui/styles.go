package ui

import "github.com/charmbracelet/lipgloss"

var (
	grayColor = lipgloss.Color("#808080")

	defaultStyle = lipgloss.NewStyle()

	blueStyle   = defaultStyle.Foreground(lipgloss.Color("#4a9eff"))
	yellowStyle = defaultStyle.Foreground(lipgloss.Color("#ffff4a"))
	greenStyle  = defaultStyle.Foreground(lipgloss.Color("#4aff9e"))
	redStyle    = defaultStyle.Foreground(lipgloss.Color("#ff4a4a"))
	grayStyle   = defaultStyle.Foreground(grayColor)
	whiteStyle  = defaultStyle.Foreground(lipgloss.Color("#ffffff"))

	defaultBoldStyle = defaultStyle.Bold(true)
	blueBoldStyle    = blueStyle.Bold(true)
	yellowBoldStyle  = yellowStyle.Bold(true)
	greenBoldStyle   = greenStyle.Bold(true)
	redBoldStyle     = redStyle.Bold(true)
	grayBoldStyle    = grayStyle.Bold(true)
	whiteBoldStyle   = whiteStyle.Bold(true)

	blueBackgroundStyle = defaultStyle.Background(lipgloss.Color("#264f88"))

	normalGrayBorder = defaultStyle.Border(lipgloss.NormalBorder()).BorderForeground(grayColor)
)
