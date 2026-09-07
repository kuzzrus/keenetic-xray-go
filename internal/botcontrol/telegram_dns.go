package botcontrol

import (
	"context"
	"fmt"
	"strings"

	"github.com/kuzzrus/keenetic-xray-go/internal/dnsupstream"
)

// The 🧭 DNS screen (under ⚙️ Порты и транспорт) points Keenetic's
// built-in dns-proxy at a chosen DoT/DoH provider or custom upstreams.
// Provider buttons come straight from the compiled-in dnsupstream
// catalogue; "📊 Проверить" asks the router to benchmark them.

func dnsScreenKB(id string) inlineKeyboard {
	var rows [][]inlineButton
	ps := dnsupstream.Providers()
	for i := 0; i < len(ps); i += 2 {
		row := []inlineButton{{Text: ps[i].Name, CallbackData: "dnp:" + id + ":" + ps[i].ID}}
		if i+1 < len(ps) {
			row = append(row, inlineButton{Text: ps[i+1].Name, CallbackData: "dnp:" + id + ":" + ps[i+1].ID})
		}
		rows = append(rows, row)
	}
	rows = append(rows,
		[]inlineButton{{Text: "📊 Проверить", CallbackData: "dntest:" + id}, {Text: "✏️ Свои", CallbackData: "dncust:" + id}},
		[]inlineButton{{Text: "⛔ Убрать наши", CallbackData: "dnoff:" + id}, {Text: "⬅️ Назад", CallbackData: "ptm:" + id}},
	)
	return inlineKeyboard{InlineKeyboard: rows}
}

const dnsScreenBlurb = "🧭 DNS %s\n\n" +
	"Прописывает роутерному dns-proxy защищённый резолвер (DoT :853 / DoH :443). " +
	"Помогает, когда провайдерский DNS отдаёт подделки на заблокированные домены — " +
	"в том числе для маршрутизации по спискам (роутер снупит ответы).\n\n" +
	"Трогаем только апстримы из этого списка — твои свои (веб-интерфейс/CLI) не задеваются. " +
	"DoH обычно живучее к DPI, чем DoT.\n\n" +
	"«📊 Проверить» — замер задержки всех провайдеров прямо с роутера.\n\n%s"

func (b *TelegramBot) openDNSScreen(ctx context.Context, cb tgCallbackQuery, id string) {
	if !b.Store.HasRouter(id) {
		b.editCB(ctx, cb, "нет такого роутера: "+id, b.routersListKB())
		return
	}
	chatID, msgID := cb.Message.Chat.ID, cb.Message.MessageID
	cmdID, err := b.Store.Enqueue(id, ActionDNSShow, nil)
	if err != nil {
		b.editCB(ctx, cb, "не поставлено в очередь: "+err.Error(), dnsScreenKB(id))
		return
	}
	b.editMessageText(ctx, chatID, msgID, fmt.Sprintf(dnsScreenBlurb, id, "⏳ читаю состояние…"), dnsScreenKB(id))
	go func() {
		state := "—"
		if res, ok := b.Store.AwaitResult(ctx, id, cmdID, b.resultTimeout()); ok {
			if res.Err != "" {
				state = "⚠️ " + res.Err
			} else if s := strings.TrimSpace(res.Output); s != "" {
				state = s
			}
		} else {
			state = "⌛ роутер не ответил"
		}
		b.editMessageText(ctx, chatID, msgID, fmt.Sprintf(dnsScreenBlurb, id, state), dnsScreenKB(id))
	}()
}

func (b *TelegramBot) openDNSProviderScreen(ctx context.Context, cb tgCallbackQuery, id, provID string) {
	p, ok := dnsupstream.Find(provID)
	if !ok {
		b.editCB(ctx, cb, "нет такого провайдера", dnsScreenKB(id))
		return
	}
	var txt strings.Builder
	fmt.Fprintf(&txt, "🧭 %s\n", p.Name)
	if p.Note != "" {
		fmt.Fprintf(&txt, "%s\n", p.Note)
	}
	txt.WriteString("\n")
	for _, t := range p.DoT {
		fmt.Fprintf(&txt, "DoT  %s  (sni %s)\n", t.IP, t.SNI)
	}
	for _, h := range p.DoH {
		fmt.Fprintf(&txt, "DoH  %s\n", h.URL)
	}
	txt.WriteString("\nЧто применить?")

	rows := [][]inlineButton{}
	if len(p.DoT) > 0 && len(p.DoH) > 0 {
		rows = append(rows, []inlineButton{
			{Text: "DoT", CallbackData: fmt.Sprintf("dna:%s:%s:dot", id, provID)},
			{Text: "DoH", CallbackData: fmt.Sprintf("dna:%s:%s:doh", id, provID)},
			{Text: "Оба", CallbackData: fmt.Sprintf("dna:%s:%s:both", id, provID)},
		})
	} else if len(p.DoT) > 0 {
		rows = append(rows, []inlineButton{{Text: "Применить (DoT)", CallbackData: fmt.Sprintf("dna:%s:%s:dot", id, provID)}})
	} else {
		rows = append(rows, []inlineButton{{Text: "Применить (DoH)", CallbackData: fmt.Sprintf("dna:%s:%s:doh", id, provID)}})
	}
	rows = append(rows, []inlineButton{{Text: "⬅️ Назад", CallbackData: "dnsm:" + id}})
	b.editCB(ctx, cb, txt.String(), inlineKeyboard{InlineKeyboard: rows})
}

// enqueueDNSAction runs one dns_* mutation then re-renders the 🧭 DNS
// screen with fresh state.
func (b *TelegramBot) enqueueDNSAction(ctx context.Context, cb tgCallbackQuery, id, action string, args []string) {
	chatID, msgID := cb.Message.Chat.ID, cb.Message.MessageID
	cmdID, err := b.Store.Enqueue(id, action, args)
	if err != nil {
		b.editCB(ctx, cb, "не поставлено в очередь: "+err.Error(), dnsScreenKB(id))
		return
	}
	b.editMessageText(ctx, chatID, msgID, fmt.Sprintf(dnsScreenBlurb, id, "⏳ …"), dnsScreenKB(id))
	go func() {
		head := "✅ готово"
		if res, ok := b.Store.AwaitResult(ctx, id, cmdID, b.resultTimeout()); !ok {
			head = "⌛ роутер не ответил"
		} else if res.Err != "" {
			head = "⚠️ " + res.Err
		} else if s := strings.TrimSpace(res.Output); s != "" {
			head = s
		}
		// pull fresh state
		state := head
		if nCmd, e := b.Store.Enqueue(id, ActionDNSShow, nil); e == nil {
			if nr, ok := b.Store.AwaitResult(ctx, id, nCmd, b.resultTimeout()); ok && nr.Err == "" {
				if s := strings.TrimSpace(nr.Output); s != "" {
					state = head + "\n\n" + s
				}
			}
		}
		b.editMessageText(ctx, chatID, msgID, fmt.Sprintf(dnsScreenBlurb, id, state), dnsScreenKB(id))
	}()
}

// startDNSCustomWizard asks for DoT/DoH upstream lines to add by hand.
func (b *TelegramBot) startDNSCustomWizard(ctx context.Context, chatID int64, routerID string) {
	if !b.Store.HasRouter(routerID) {
		b.sendMessage(ctx, chatID, "нет такого роутера: "+routerID)
		return
	}
	b.wizardMu.Lock()
	b.wizards[chatID] = &wizState{step: wizDNSCustom, routerID: routerID}
	b.wizardMu.Unlock()
	b.sendMessage(ctx, chatID, "🧭 DNS "+routerID+" — свои апстримы.\n\n"+
		"По одному в строке:\n"+
		"• DoH:  https://dns.example/dns-query\n"+
		"• DoT:  1.2.3.4 sni dns.example\n\n"+
		"Можно вперемешку. Отмена: /cancel")
}

// wizardDNSCustom classifies pasted lines into DoT pairs and DoH URLs and
// applies them (dns_set dot / dns_set doh).
func (b *TelegramBot) wizardDNSCustom(ctx context.Context, chatID int64, st *wizState, text string) {
	var dotPairs, dohURLs []string
	for _, ln := range strings.Split(text, "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" {
			continue
		}
		if strings.HasPrefix(ln, "https://") {
			dohURLs = append(dohURLs, strings.Fields(ln)[0])
			continue
		}
		f := strings.Fields(ln)
		switch {
		case len(f) == 3 && f[1] == "sni":
			dotPairs = append(dotPairs, f[0], f[2])
		case len(f) == 2:
			dotPairs = append(dotPairs, f[0], f[1])
		default:
			b.sendMessage(ctx, chatID, "не разобрал строку: "+ln+"\nФормат: «https://…» или «ip sni host». Ещё раз или /cancel")
			return
		}
	}
	if len(dotPairs) == 0 && len(dohURLs) == 0 {
		b.sendMessage(ctx, chatID, "пусто. Ещё раз или /cancel")
		return
	}
	b.wizardClear(chatID)

	var msgs []string
	if len(dotPairs) > 0 {
		out, answered, errText := b.enqueueAndWait(ctx, st.routerID, ActionDNSSet, []string{"dot", strings.Join(dotPairs, " ")})
		msgs = append(msgs, b.stepResult(st.routerID, answered, errText, strings.TrimSpace(out)))
	}
	if len(dohURLs) > 0 {
		out, answered, errText := b.enqueueAndWait(ctx, st.routerID, ActionDNSSet, []string{"doh", strings.Join(dohURLs, " ")})
		msgs = append(msgs, b.stepResult(st.routerID, answered, errText, strings.TrimSpace(out)))
	}
	b.sendMessage(ctx, chatID, strings.Join(msgs, "\n\n"))
}

// handleDNSCallback handles every dn* callback. Returns false if data
// isn't one of ours.
func (b *TelegramBot) handleDNSCallback(ctx context.Context, cb tgCallbackQuery, data string) bool {
	switch {
	case strings.HasPrefix(data, "dnsm:"):
		b.openDNSScreen(ctx, cb, strings.TrimPrefix(data, "dnsm:"))
	case strings.HasPrefix(data, "dnp:"):
		rest := strings.TrimPrefix(data, "dnp:")
		id, prov, ok := strings.Cut(rest, ":")
		if ok {
			b.openDNSProviderScreen(ctx, cb, id, prov)
		}
	case strings.HasPrefix(data, "dna:"):
		f := strings.Split(strings.TrimPrefix(data, "dna:"), ":")
		if len(f) != 3 {
			return true
		}
		b.enqueueDNSAction(ctx, cb, f[0], ActionDNSPreset, []string{f[1], f[2]})
	case strings.HasPrefix(data, "dntest:"):
		b.enqueueDNSAction(ctx, cb, strings.TrimPrefix(data, "dntest:"), ActionDNSTest, nil)
	case strings.HasPrefix(data, "dnoff:"):
		b.enqueueDNSAction(ctx, cb, strings.TrimPrefix(data, "dnoff:"), ActionDNSOff, nil)
	case strings.HasPrefix(data, "dncust:"):
		b.startDNSCustomWizard(ctx, cb.Message.Chat.ID, strings.TrimPrefix(data, "dncust:"))
	default:
		return false
	}
	return true
}
