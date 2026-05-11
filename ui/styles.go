package ui

import (
	"github.com/charmbracelet/bubbles/help"
	"github.com/charmbracelet/lipgloss"
)

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

// newHelpModel returns a help.Model with the footer key/description styling
// used everywhere in nftui:
//   - Key: bold blue (same blue as the app accent) — the "actionable handle".
//   - Description: light gray — supplementary; lower visual weight than the key.
//   - Separator: dim gray.
//
// Use this everywhere instead of help.New(), so the footer styling stays
// consistent across views.
func newHelpModel() help.Model {
	h := help.New()
	keyStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#4a9eff")).
		Bold(true)
	descStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#cccccc"))
	sepStyle := lipgloss.NewStyle().
		Foreground(grayColor)
	h.Styles.ShortKey = keyStyle
	h.Styles.ShortDesc = descStyle
	h.Styles.ShortSeparator = sepStyle
	h.Styles.FullKey = keyStyle
	h.Styles.FullDesc = descStyle
	h.Styles.FullSeparator = sepStyle
	return h
}
