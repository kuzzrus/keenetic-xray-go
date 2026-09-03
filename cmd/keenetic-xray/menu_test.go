package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRunMenu_EOFQuits(t *testing.T) {
	var out bytes.Buffer
	if err := runMenu(strings.NewReader(""), &out); err != nil {
		t.Fatalf("runMenu on empty input: %v", err)
	}
	if !strings.Contains(out.String(), "1) Статус") {
		t.Errorf("menu was never rendered:\n%s", out.String())
	}
}

func TestRunMenu_ExplicitQuit(t *testing.T) {
	for _, in := range []string{"0\n", "q\n", "exit\n"} {
		var out bytes.Buffer
		if err := runMenu(strings.NewReader(in), &out); err != nil {
			t.Fatalf("runMenu(%q): %v", in, err)
		}
	}
}

func TestRunMenu_UnknownChoiceRepromptsThenQuits(t *testing.T) {
	var out bytes.Buffer
	if err := runMenu(strings.NewReader("99\n0\n"), &out); err != nil {
		t.Fatalf("runMenu: %v", err)
	}
	s := out.String()
	if !strings.Contains(s, "неизвестный пункт") {
		t.Errorf("bad choice not reported:\n%s", s)
	}
	if n := strings.Count(s, "1) Статус"); n < 2 {
		t.Errorf("menu rendered %d times, want >= 2 (reprompt after bad choice)", n)
	}
}

func TestRunMenu_BlankLineRedraws(t *testing.T) {
	var out bytes.Buffer
	if err := runMenu(strings.NewReader("\n\n0\n"), &out); err != nil {
		t.Fatalf("runMenu: %v", err)
	}
	s := out.String()
	if strings.Contains(s, "неизвестный пункт") {
		t.Errorf("blank line should redraw silently, not warn:\n%s", s)
	}
	if n := strings.Count(s, "1) Статус"); n < 3 {
		t.Errorf("menu rendered %d times, want >= 3 (two blank lines + initial)", n)
	}
}

// The menu chrome is the new logic; each subcommand it calls is tested
// on its own. These check that a choice reaches the right handler by
// asserting on text the handler writes to the menu's own io.Writer.

func TestRunMenu_RestartChoiceReachesHandler(t *testing.T) {
	var out bytes.Buffer
	if err := runMenu(strings.NewReader("7\n0\n"), &out); err != nil {
		t.Fatalf("runMenu: %v", err)
	}
	// Off-router (no init script) the restart handler says so.
	if !strings.Contains(out.String(), "init-скрипт не найден") {
		t.Errorf("choice 7 did not reach menuRestartDaemon:\n%s", out.String())
	}
}

func TestRunMenu_Proxy0ChoiceReachesSubmenu(t *testing.T) {
	var out bytes.Buffer
	if err := runMenu(strings.NewReader("6\na\n0\n"), &out); err != nil {
		t.Fatalf("runMenu: %v", err)
	}
	if !strings.Contains(out.String(), "показать") {
		t.Errorf("choice 6 did not open the proxy0 submenu:\n%s", out.String())
	}
}
