package ui

import (
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/google/nftables"
	"nftui/nft"
)

type CommentField struct {
	input    textinput.Model
	original string
}

func NewCommentField(rd *nft.Rule) *CommentField {
	input := textinput.New()
	input.Placeholder = "Comment"
	input.CharLimit = 256
	input.Width = 80

	input.SetValue(rd.Comment)
	return &CommentField{input: input, original: rd.Comment}
}

func (f *CommentField) FocusSlots() int { return 1 }
func (f *CommentField) Focus(_ int)     { f.input.Focus() }
func (f *CommentField) Blur()           { f.input.Blur() }

func (f *CommentField) Changed() bool {
	return f.input.Value() != f.original
}

func (f *CommentField) Update(msg tea.Msg) tea.Cmd {
	var cmd tea.Cmd
	f.input, cmd = f.input.Update(msg)
	return cmd
}

func (f *CommentField) Save(rule *nftables.Rule) {
	if !f.Changed() {
		return
	}
	newComment := f.input.Value()
	rule.UserData = encodeCommentToUserData(newComment)
	f.original = newComment
}

func (f *CommentField) View() string {
	v := f.input.View()
	if f.Changed() {
		v = lipgloss.NewStyle().Foreground(lipgloss.Color("220")).Render(v)
	}
	return grayStyle.Render("Comment") + "\n" + v + "\n"
}
