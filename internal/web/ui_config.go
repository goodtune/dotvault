package web

import (
	"net/http"
	"sort"
)

// The config view types are shared between GET /api/v1/config (which
// marshals them as JSON, preserving the historical wire shape) and the
// server-rendered /ui/config/ page (which renders them through config.tmpl).
// One builder means the two surfaces cannot drift.

type targetView struct {
	Path        string `json:"path"`
	Format      string `json:"format"`
	Merge       string `json:"merge,omitempty"`
	HasTemplate bool   `json:"has_template"`
}

type oauthView struct {
	Provider   string   `json:"provider"`
	EnginePath string   `json:"engine_path,omitempty"`
	Scopes     []string `json:"scopes,omitempty"`
}

type ruleView struct {
	Name        string     `json:"name"`
	Description string     `json:"description,omitempty"`
	VaultKey    string     `json:"vault_key"`
	Target      targetView `json:"target"`
	OAuth       *oauthView `json:"oauth,omitempty"`
}

type enrolmentView struct {
	Key        string         `json:"key"`
	Engine     string         `json:"engine"`
	EngineName string         `json:"engine_name,omitempty"`
	Fields     []string       `json:"fields,omitempty"`
	Settings   map[string]any `json:"settings,omitempty"`
	Status     string         `json:"status,omitempty"`
}

type configVaultView struct {
	Address             string `json:"address"`
	KVMount             string `json:"kv_mount"`
	UserPrefix          string `json:"user_prefix"`
	AuthMethod          string `json:"auth_method"`
	AuthMount           string `json:"auth_mount"`
	AuthRole            string `json:"auth_role"`
	TLSSkipVerify       bool   `json:"tls_skip_verify"`
	HasCACert           bool   `json:"has_ca_cert"`
	DisableTokenRenewal bool   `json:"disable_token_renewal"`
}

type configSyncView struct {
	Interval string `json:"interval"`
}

type configWebView struct {
	Enabled         bool   `json:"enabled"`
	Listen          string `json:"listen"`
	ListenEffective string `json:"listen_effective,omitempty"`
}

type configRemoteView struct {
	URL             string   `json:"url"`
	RefreshInterval string   `json:"refresh_interval"`
	HasCACert       bool     `json:"has_ca_cert"`
	HeaderNames     []string `json:"header_names,omitempty"`
}

type configView struct {
	Vault        configVaultView   `json:"vault"`
	Sync         configSyncView    `json:"sync"`
	Web          configWebView     `json:"web"`
	Rules        []ruleView        `json:"rules"`
	Enrolments   []enrolmentView   `json:"enrolments"`
	RemoteConfig *configRemoteView `json:"remote_config,omitempty"`
}

// buildConfigViewModel assembles the redacted effective-configuration view
// served by GET /api/v1/config and rendered on /ui/config/.
func (s *Server) buildConfigViewModel() configView {
	currentRules := s.getRules()
	rules := make([]ruleView, len(currentRules))
	for i, rule := range currentRules {
		rules[i] = ruleView{
			Name:        rule.Name,
			Description: rule.Description,
			VaultKey:    rule.VaultKey,
			Target: targetView{
				Path:        rule.Target.Path,
				Format:      rule.Target.Format,
				Merge:       rule.Target.Merge,
				HasTemplate: rule.Target.Template != "",
			},
		}
		if rule.OAuth != nil {
			rules[i].OAuth = &oauthView{
				Provider:   rule.OAuth.Provider,
				EnginePath: rule.OAuth.EnginePath,
				Scopes:     rule.OAuth.Scopes,
			}
		}
	}

	statuses := map[string]EnrolStateInfo{}
	if runner := s.getEnrolRunner(); runner != nil {
		for _, st := range runner.States() {
			statuses[st.Key] = st
		}
	}

	enrolmentMap := s.getEnrolments()
	keys := make([]string, 0, len(enrolmentMap))
	for k := range enrolmentMap {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	enrolments := make([]enrolmentView, 0, len(keys))
	for _, k := range keys {
		e := enrolmentMap[k]
		ev := enrolmentView{
			Key:      k,
			Engine:   e.Engine,
			Settings: redactEnrolmentSettings(e.Settings),
		}
		if st, ok := statuses[k]; ok {
			ev.EngineName = st.EngineName
			ev.Fields = st.Fields
			ev.Status = st.Status
		}
		enrolments = append(enrolments, ev)
	}

	currentSync := s.getSyncCfg()
	syncInterval := currentSync.RawInterval
	if syncInterval == "" && currentSync.Interval > 0 {
		syncInterval = formatDuration(currentSync.Interval)
	}

	view := configView{
		Vault: configVaultView{
			Address:    s.vaultCfg.Address,
			KVMount:    s.kvMount,
			UserPrefix: s.userPrefix,
			// The effective-config view shows the raw configured method
			// (including any "+tpm" suffix) so it matches the lossless
			// config-download and honestly reflects token-sealing. Only the
			// SPA login dispatch on /api/v1/status needs the base form.
			AuthMethod:          s.vaultCfg.AuthMethod,
			AuthMount:           s.authMount,
			AuthRole:            s.authRole,
			TLSSkipVerify:       s.vaultCfg.TLSSkipVerify,
			HasCACert:           s.vaultCfg.CACert != "",
			DisableTokenRenewal: s.vaultCfg.DisableTokenRenewal,
		},
		Sync: configSyncView{Interval: syncInterval},
		Web: configWebView{
			Enabled: s.cfg.Enabled,
			Listen:  s.cfg.Listen,
			// listen_effective surfaces the actually-bound address, which
			// differs from the configured value when the user gave a port
			// like ":0".
			ListenEffective: s.listenAddr,
		},
		Rules:      rules,
		Enrolments: enrolments,
	}

	// Remote-config overlay summary. The redacted view exposes the header
	// *names* only — values are operator-defined dimension labels and flow
	// through the lossless download endpoint instead, mirroring how
	// observability headers are handled.
	if s.remoteCfg.URL != "" {
		rc := &configRemoteView{
			URL:             s.remoteCfg.URL,
			RefreshInterval: s.remoteCfg.RawRefreshInterval,
			HasCACert:       s.remoteCfg.CACert != "",
		}
		if len(s.remoteCfg.Headers) > 0 {
			names := make([]string, 0, len(s.remoteCfg.Headers))
			for k := range s.remoteCfg.Headers {
				names = append(names, k)
			}
			sort.Strings(names)
			rc.HeaderNames = names
		}
		view.RemoteConfig = rc
	}
	return view
}

// handleUIConfig renders /ui/config/ — the Effective Configuration screen,
// with the left navigation kept in place (which is what makes a "back to
// dashboard" button unnecessary here).
func (s *Server) handleUIConfig(w http.ResponseWriter, r *http.Request) {
	if !s.requireUIPage(w, r) {
		return
	}
	data := struct {
		uiPageData
		Config configView
	}{
		uiPageData: s.uiBase(r.Context(), "Configuration", "", ""),
		Config:     s.buildConfigViewModel(),
	}
	s.uiRenderPage(w, "config", data)
}
