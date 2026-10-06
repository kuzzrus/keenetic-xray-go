package depscan

import "strings"

// The three lists below are heuristics for how a found host is *shown*
// and which ones start out ticked -- never for whether it may be added:
// the operator decides that. Each entry is a domain; a host matches it
// when it is that domain or any subdomain of it.

// sharedSuffixes are services that thousands of unrelated sites pull
// from: a library CDN, a font host, an embedded-video domain. A route
// entry for one of them sends every other site's traffic to that host
// through the tunnel as well, which is usually harmless (it was blocked
// for them too) but worth saying out loud. A *tenant* hostname on a big
// platform (d111.cloudfront.net, a bucket on amazonaws.com) is not on
// this list: the exact host is specific to one site, and the scan only
// ever suggests exact hosts, never a whole platform zone.
var sharedSuffixes = []string{
	"jsdelivr.net", "unpkg.com", "cdnjs.cloudflare.com", "googleapis.com",
	"gstatic.com", "bootstrapcdn.com", "fontawesome.com", "typekit.net",
	"gravatar.com", "youtube.com", "youtube-nocookie.com", "ytimg.com",
	"google.com", "googleusercontent.com", "ggpht.com", "twimg.com",
	"jquery.com", "vimeo.com", "vimeocdn.com", "recaptcha.net",
	"hcaptcha.com", "cloudflare.com", "w.org", "wp.com",
}

// trackerSuffixes are advertising, analytics and telemetry hosts. They
// are found on nearly every page, are rarely what makes a page work, and
// routing them through the tunnel mostly adds traffic -- so they are
// never ticked by default, even when they do not open directly.
var trackerSuffixes = []string{
	"doubleclick.net", "googlesyndication.com", "googletagmanager.com",
	"googletagservices.com", "google-analytics.com", "googleadservices.com",
	"facebook.net", "mc.yandex.ru", "mc.yandex.com", "an.yandex.ru",
	"yandexadexchange.net", "adfox.ru", "top.mail.ru", "top-fwz1.mail.ru",
	"counter.yadro.ru", "hotjar.com", "hotjar.io", "sentry.io",
	"newrelic.com", "nr-data.net", "scorecardresearch.com", "criteo.com",
	"criteo.net", "taboola.com", "outbrain.com", "adnxs.com",
	"amazon-adsystem.com", "rubiconproject.com", "pubmatic.com",
	"openx.net", "casalemedia.com", "adsrvr.org", "segment.io",
	"segment.com", "mixpanel.com", "amplitude.com", "fullstory.com",
	"clarity.ms", "cloudflareinsights.com", "onesignal.com", "appsflyer.com",
	"adjust.com", "ads.twitter.com", "analytics.tiktok.com",
	"px.ads.linkedin.com", "snap.licdn.com", "bat.bing.com",
}

// ignoredSuffixes are names that appear in markup and scripts as
// identifiers -- XML namespaces, schema URLs -- not as servers a page
// talks to.
var ignoredSuffixes = []string{
	"w3.org", "schema.org", "ogp.me", "xmlns.com", "purl.org",
	"xmlsoap.org", "json-schema.org", "sitemaps.org", "openid.net",
}

// internalSuffixes are names that never resolve on the public internet.
var internalSuffixes = []string{
	"local", "lan", "internal", "localhost", "localdomain", "home.arpa",
	"corp", "home", "intranet", "private", "invalid", "test",
}

// inSuffixes reports whether host is one of list or a subdomain of one.
func inSuffixes(host string, list []string) bool {
	for _, s := range list {
		if host == s || strings.HasSuffix(host, "."+s) {
			return true
		}
	}
	return false
}
