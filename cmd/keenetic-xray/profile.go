package main

import (
	"fmt"
	"strconv"

	"github.com/kuzzrus/keenetic-xray-go/internal/config"
)

func cmdProfile(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: keenetic-xray profile {add|list|remove} ...")
	}
	switch args[0] {
	case "add":
		return profileAdd(args[1:])
	case "list":
		return profileList()
	case "remove":
		return profileRemove(args[1:])
	default:
		return fmt.Errorf("unknown profile subcommand %q", args[0])
	}
}

func profileAdd(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: keenetic-xray profile add <vless-uri>")
	}
	p, err := config.ParseVLESSURI(args[0])
	if err != nil {
		return fmt.Errorf("parsing vless URI: %w", err)
	}

	cfg, err := config.Load(configPath())
	if err != nil {
		return err
	}
	cfg.Profiles = append(cfg.Profiles, p)
	if err := cfg.Save(configPath()); err != nil {
		return err
	}
	fmt.Printf("added profile %d: %s (%s)\n", len(cfg.Profiles)-1, p.Remark, p.Address)
	return nil
}

func profileList() error {
	cfg, err := config.Load(configPath())
	if err != nil {
		return err
	}
	if len(cfg.Profiles) == 0 {
		fmt.Println("no profiles configured -- run `keenetic-xray setup`")
		return nil
	}
	for i, p := range cfg.Profiles {
		marker := ""
		if i == cfg.PrimaryIndex {
			marker += " [primary]"
		}
		if i == cfg.BackupIndex {
			marker += " [backup]"
		}
		fmt.Printf("%d: %s -- %s:%d (%s/%s)%s\n", i, p.Remark, p.Address, p.Port, p.Network, p.Security, marker)
	}
	return nil
}

func profileRemove(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: keenetic-xray profile remove <index>")
	}
	idx, err := strconv.Atoi(args[0])
	if err != nil {
		return fmt.Errorf("invalid index %q: %w", args[0], err)
	}

	cfg, err := config.Load(configPath())
	if err != nil {
		return err
	}
	if idx < 0 || idx >= len(cfg.Profiles) {
		return fmt.Errorf("index %d out of range (%d profiles)", idx, len(cfg.Profiles))
	}

	cfg.Profiles = append(cfg.Profiles[:idx], cfg.Profiles[idx+1:]...)
	cfg.PrimaryIndex = reindexAfterRemoval(cfg.PrimaryIndex, idx)
	cfg.BackupIndex = reindexAfterRemoval(cfg.BackupIndex, idx)

	if err := cfg.Save(configPath()); err != nil {
		return err
	}
	fmt.Printf("removed profile %d\n", idx)
	return nil
}

// reindexAfterRemoval adjusts an index after the profile at removedIdx was
// deleted: the removed slot's own selection is cleared (-1), later indices
// shift down by one, earlier ones are untouched.
func reindexAfterRemoval(current, removedIdx int) int {
	switch {
	case current == removedIdx:
		return -1
	case current > removedIdx:
		return current - 1
	default:
		return current
	}
}
