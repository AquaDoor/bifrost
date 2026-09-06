package server

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"os"
	"slices"
	"time"

	"github.com/maximhq/bifrost/core/schemas"
	aquadoordefaultprovider "github.com/maximhq/bifrost/plugins/aquadoor-defaultprovider"
	aquadoorobo "github.com/maximhq/bifrost/plugins/aquadoor-obo"
	aquadoorpii "github.com/maximhq/bifrost/plugins/aquadoor-pii"
	aquadoorusermeter "github.com/maximhq/bifrost/plugins/aquadoor-usermeter"
	"github.com/maximhq/bifrost/plugins/compat"
	"github.com/maximhq/bifrost/plugins/governance"
	"github.com/maximhq/bifrost/plugins/logging"
	"github.com/maximhq/bifrost/plugins/maxim"
	"github.com/maximhq/bifrost/plugins/modelcatalogresolver"
	"github.com/maximhq/bifrost/plugins/otel"
	"github.com/maximhq/bifrost/plugins/prompts"
	"github.com/maximhq/bifrost/plugins/routing"
	"github.com/maximhq/bifrost/plugins/semanticcache"
	"github.com/maximhq/bifrost/plugins/telemetry"
	"github.com/maximhq/bifrost/transports/bifrost-http/handlers"
	"github.com/maximhq/bifrost/transports/bifrost-http/lib"
)

// InferPluginTypes determines which interface types a plugin implements
func InferPluginTypes(plugin schemas.BasePlugin) []schemas.PluginType {
	var types []schemas.PluginType
	if _, ok := plugin.(schemas.LLMPlugin); ok {
		types = append(types, schemas.PluginTypeLLM)
	}
	if _, ok := plugin.(schemas.MCPPlugin); ok {
		types = append(types, schemas.PluginTypeMCP)
	}
	if _, ok := plugin.(schemas.HTTPTransportPlugin); ok {
		types = append(types, schemas.PluginTypeHTTP)
	}
	return types
}

// Single-plugin methods used plugin create/update

// InstantiatePlugin creates a plugin instance but does NOT register it
// Registration is done separately via Config.RegisterPlugin()
func InstantiatePlugin(ctx context.Context, name string, path *string, pluginConfig any, bifrostConfig *lib.Config) (schemas.BasePlugin, error) {
	// Custom plugin (has path)
	if path != nil {
		return loadCustomPlugin(ctx, path, pluginConfig, bifrostConfig)
	}

	// Built-in plugin (by name)
	return loadBuiltinPlugin(ctx, name, pluginConfig, bifrostConfig)
}

// loadBuiltinPlugin instantiates a built-in plugin by name
func loadBuiltinPlugin(ctx context.Context, name string, pluginConfig any, bifrostConfig *lib.Config) (schemas.BasePlugin, error) {
	switch name {
	case telemetry.PluginName:
		telConfig := &telemetry.Config{
			CustomLabels: bifrostConfig.ClientConfig.PrometheusLabels,
		}
		// Merge persisted config if provided.
		if pluginConfig != nil {
			extraConfig, err := MarshalPluginConfig[telemetry.Config](pluginConfig)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal telemetry plugin config: %w", err)
			}
			if extraConfig != nil {
				if extraConfig.PushGateway != nil {
					telConfig.PushGateway = extraConfig.PushGateway
				}
				if extraConfig.MetricsEnabled != nil {
					telConfig.MetricsEnabled = extraConfig.MetricsEnabled
				}
			}
		}
		return telemetry.Init(telConfig, bifrostConfig.ModelCatalog, logger)

	case prompts.PluginName:
		return prompts.Init(ctx, bifrostConfig.ConfigStore, logger)

	case logging.PluginName:
		loggingConfig, err := MarshalPluginConfig[logging.Config](pluginConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal logging plugin config: %w", err)
		}
		if loggingConfig != nil {
			loggingConfig.ObjectStorageEnabled = bifrostConfig.LogsStoreConfig != nil &&
				bifrostConfig.LogsStoreConfig.ObjectStorage != nil
		}
		return logging.Init(ctx, loggingConfig, logger, bifrostConfig.LogsStore,
			bifrostConfig.ConfigStore, bifrostConfig.ModelCatalog, bifrostConfig.MCPCatalog)

	case governance.PluginName:
		governanceConfig, err := MarshalPluginConfig[governance.Config](pluginConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal governance plugin config: %w", err)
		}
		inMemoryStore := &GovernanceInMemoryStore{Config: bifrostConfig}
		return governance.Init(ctx, governanceConfig, logger, bifrostConfig.ConfigStore,
			bifrostConfig.GovernanceConfig, bifrostConfig.ModelCatalog,
			bifrostConfig.MCPCatalog, inMemoryStore)

	case routing.PluginName:
		routingConfig, err := MarshalPluginConfig[routing.Config](pluginConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal routing plugin config: %w", err)
		}
		if routingConfig == nil {
			routingConfig = &routing.Config{}
		}
		// Session complexity state uses the same process-wide store as core
		// session routing. The field is runtime-only and is never persisted in
		// plugin configuration.
		routingConfig.KVStore = bifrostConfig.KVStore
		// Routing rules read the virtual key and its live budget/rate-limit usage, so the
		// governance plugin must already be registered when this runs.
		governancePlugin, err := lib.FindPluginAs[governance.BaseGovernancePlugin](bifrostConfig, governancePluginNameFromContext(ctx))
		if err != nil {
			return nil, fmt.Errorf("routing plugin requires the governance plugin: %w", err)
		}
		return routing.Init(ctx, routingConfig, logger, bifrostConfig.ConfigStore, governancePlugin)

	case maxim.PluginName:
		maximConfig, err := MarshalPluginConfig[maxim.Config](pluginConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal maxim plugin config: %w", err)
		}
		return maxim.Init(maximConfig, logger)

	case semanticcache.PluginName:
		semanticConfig, err := MarshalPluginConfig[semanticcache.Config](pluginConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal semantic cache plugin config: %w", err)
		}
		return semanticcache.Init(ctx, semanticConfig, logger, bifrostConfig.VectorStore)

	case otel.PluginName:
		otelConfig, err := MarshalPluginConfig[otel.Config](pluginConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal otel plugin config: %w", err)
		}
		return otel.Init(ctx, otelConfig, logger, bifrostConfig.ModelCatalog, handlers.GetVersion())

	case compat.PluginName:
		compatConfig, err := MarshalPluginConfig[compat.Config](pluginConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal compat plugin config: %w", err)
		}
		return compat.Init(*compatConfig, logger, bifrostConfig.ModelCatalog)

	case modelcatalogresolver.PluginName:
		return modelcatalogresolver.Init(bifrostConfig.ModelCatalog, logger)

	case "aquadoor-default-provider":
		// AquaDoor default-provider hook (#1780 §7.7 / #1801 / G006): route bare/unknown-prefix model
		// names (LibreChat chat/RAG/memory) to the AquaDoor LLM provider so egress flows through
		// Bifrost (pii + governance) without per-model prefixing. Config-driven ({Provider}); empty →
		// self-disabled. MUST be registered BEFORE governance so the defaulted provider is what
		// governance + validateRequestAfterPreRequestHooks see.
		cfg, err := MarshalPluginConfig[aquadoordefaultprovider.Config](pluginConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal aquadoor-default-provider plugin config: %w", err)
		}
		if cfg == nil {
			cfg = &aquadoordefaultprovider.Config{}
		}
		return aquadoordefaultprovider.New(*cfg), nil

	case "aquadoor-pii":
		// AquaDoor fail-closed RU PII egress guardrail (#1780 §7.5). In-process recognition (no
		// external Presidio service). Config-driven (language, entities, block-entities); no secrets,
		// no runtime deps.
		cfg, err := MarshalPluginConfig[aquadoorpii.Config](pluginConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal aquadoor-pii plugin config: %w", err)
		}
		if cfg == nil {
			cfg = &aquadoorpii.Config{}
		}
		return aquadoorpii.New(*cfg), nil

	case "aquadoor-obo":
		// AquaDoor verified-identity OBO on runner MCP calls (#1780 §7.2, #1777). Non-secret config
		// (issuer, project id, client id, runner clients/prefixes, strategy) comes from config.json;
		// the two SECRETS — the Zitadel MachineKey (actor key JSON) and the upstream client secret —
		// come from env, never config.json. The email is resolved from the governance-verified VK
		// name in context (GovernanceVKNameResolver), so OBO must run AFTER governance.
		cfg, err := MarshalPluginConfig[aquadoorobo.Config](pluginConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal aquadoor-obo plugin config: %w", err)
		}
		if cfg == nil {
			cfg = &aquadoorobo.Config{}
		}
		if raw := os.Getenv("AQUADOOR_OBO_ACTOR_KEY_JSON"); raw != "" {
			var ak aquadoorobo.ActorKey
			if err := json.Unmarshal([]byte(raw), &ak); err != nil {
				return nil, fmt.Errorf("aquadoor-obo: invalid AQUADOOR_OBO_ACTOR_KEY_JSON: %w", err)
			}
			cfg.ActorKey = ak
		}
		if s := os.Getenv("AQUADOOR_OBO_UPSTREAM_CLIENT_SECRET"); s != "" {
			cfg.UpstreamClientSecret = s
		}
		// Gateway identity assertion (#1804 / #1798-A3): the RS256 PRIVATE key is a SECRET (env, never
		// config.json — mirrors the actor key). iss/aud come from config.json (non-secret). Empty key →
		// no assertion is minted (identity enrichment self-disabled, like the rest of OBO env).
		if s := os.Getenv("AQUADOOR_GATEWAY_IDENTITY_PRIVATE_KEY"); s != "" {
			cfg.IdentityPrivateKey = s
		}
		timeout := cfg.HTTPTimeout
		if timeout <= 0 {
			timeout = 10 * time.Second
		}
		svc := aquadoorobo.NewService(*cfg, &http.Client{Timeout: timeout})
		return aquadoorobo.NewPlugin(svc, cfg.RunnerClients, aquadoorobo.GovernanceVKNameResolver{}, logger), nil

	case aquadoorusermeter.PluginName:
		// AquaDoor per-user LLM cost metering (#1814). In HTTPTransportPreAuthHook it swaps a
		// LibreChat-vouched end-user email (X-Aquadoor-User-Email) to that user's per-user VK so
		// governance meters cost/budget/rate PER USER. Non-secret config (EmailHeader, CacheTTL) may
		// come from config.json; the trusted-asserter VK (the LibreChat service VK) is a SECRET → env,
		// never config.json (mirrors aquadoor-obo). Empty asserter or no config store → self-disabled
		// (pass-through). email→VK resolution uses the config store's by-name lookup.
		cfg, err := MarshalPluginConfig[aquadoorusermeter.Config](pluginConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal aquadoor-usermeter plugin config: %w", err)
		}
		if cfg == nil {
			cfg = &aquadoorusermeter.Config{}
		}
		if v := os.Getenv("AQUADOOR_USERMETER_ASSERTER_VK"); v != "" {
			cfg.AsserterVK = v
		}
		// The RDB config store implements GetVirtualKeyByName; a nil/other store → New self-disables.
		store, _ := bifrostConfig.ConfigStore.(aquadoorusermeter.VKStore)
		return aquadoorusermeter.New(*cfg, store, logger), nil

	default:
		return nil, fmt.Errorf("unknown built-in plugin: %s", name)
	}
}

// loadCustomPlugin loads a plugin from a shared object file
func loadCustomPlugin(ctx context.Context, path *string, pluginConfig any, bifrostConfig *lib.Config) (schemas.BasePlugin, error) {
	logger.Info("loading custom plugin from path %s", *path)

	plugin, err := bifrostConfig.PluginLoader.LoadPlugin(*path, pluginConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to load custom plugin: %w", err)
	}
	return plugin, nil
}

// LoadPlugins loads the plugins for the server.
func (s *BifrostHTTPServer) LoadPlugins(ctx context.Context) error {
	// Load built-in plugins first (order matters)
	if err := s.loadBuiltinPlugins(ctx); err != nil {
		return err
	}
	// Load custom plugins from config
	if err := s.loadCustomPlugins(ctx); err != nil {
		return err
	}
	// Sort all plugins by placement group and order
	s.Config.SortAndRebuildPlugins()
	return nil
}

// getPluginConfig retrieves a plugin's config from PluginConfigs by name
func (s *BifrostHTTPServer) getPluginConfig(name string) *schemas.PluginConfig {
	for _, cfg := range s.Config.PluginConfigs {
		if cfg.Name == name {
			return cfg
		}
	}
	return nil
}

// loadBuiltinPlugins loads required built-in plugins in specific order
func (s *BifrostHTTPServer) loadBuiltinPlugins(ctx context.Context) error {
	builtinPlacement := schemas.Ptr(schemas.PluginPlacementBuiltin)

	// 1. Telemetry (always first - tracks everything).
	// Default-on: absent PluginConfig entry is treated as enabled, matching pre-#3269 behavior
	// so upgraders don't silently lose /metrics. Only an explicit Enabled=false disables it.
	telemetryPluginConfig := s.getPluginConfig(telemetry.PluginName)
	var pluginConfig any
	if telemetryPluginConfig != nil {
		pluginConfig = telemetryPluginConfig.Config
	}
	if telemetryPluginConfig == nil || telemetryPluginConfig.Enabled {
		s.registerPluginWithStatus(ctx, telemetry.PluginName, nil, pluginConfig, false)
	} else {
		s.markPluginDisabled(telemetry.PluginName)
	}
	s.Config.SetPluginOrderInfo(telemetry.PluginName, builtinPlacement, schemas.Ptr(1))

	// 2. Prompts (requires config store for prompt repository; disabled in enterprise)
	if s.Config.ConfigStore != nil && ctx.Value(schemas.BifrostContextKeyIsEnterprise) == nil {
		s.registerPluginWithStatus(ctx, prompts.PluginName, nil, nil, false)
	} else {
		s.markPluginDisabled(prompts.PluginName)
	}
	s.Config.SetPluginOrderInfo(prompts.PluginName, builtinPlacement, schemas.Ptr(2))

	// 3. Logging (if enabled)
	if (s.Config.ClientConfig.EnableLogging == nil || *s.Config.ClientConfig.EnableLogging) && s.Config.LogsStore != nil {
		config := &logging.Config{
			DisableContentLogging:        &s.Config.ClientConfig.DisableContentLogging,
			RetainContentInObjectStorage: &s.Config.ClientConfig.RetainContentInObjectStorage,
			LoggingHeaders:               &s.Config.ClientConfig.LoggingHeaders,
		}
		if s.Config.LogsStoreConfig != nil {
			config.Writer = s.Config.LogsStoreConfig.Writer
		}
		s.registerPluginWithStatus(ctx, logging.PluginName, nil, config, false)
	} else {
		s.markPluginDisabled(logging.PluginName)
	}
	s.Config.SetPluginOrderInfo(logging.PluginName, builtinPlacement, schemas.Ptr(3))

	// 4. Governance (if enabled and not enterprise)
	if ctx.Value(schemas.BifrostContextKeyIsEnterprise) == nil {
		config := &governance.Config{
			IsVkMandatory:         &s.Config.ClientConfig.EnforceAuthOnInference,
			RequiredHeaders:       &s.Config.ClientConfig.RequiredHeaders,
			DisableAutoToolInject: &s.Config.ClientConfig.MCPDisableAutoToolInject,
		}
		s.registerPluginWithStatus(ctx, governance.PluginName, nil, config, false)
	} else {
		s.markPluginDisabled(governance.PluginName)
	}
	s.Config.SetPluginOrderInfo(governance.PluginName, builtinPlacement, schemas.Ptr(4))

	// 5. Routing rules. Runs after governance so rules evaluate against a fully stamped
	// context, and drives the rest of the routing pipeline itself: it publishes the virtual
	// key's provider allowlist and load balances its providers once a rule has decided.
	if s.Config.IsPluginLoaded(s.getGovernancePluginName()) {
		config := &routing.Config{
			ChainMaxDepth: &s.Config.ClientConfig.RoutingChainMaxDepth,
		}
		s.registerPluginWithStatus(ctx, routing.PluginName, nil, config, false)
	} else {
		s.markPluginDisabled(routing.PluginName)
	}
	s.Config.SetPluginOrderInfo(routing.PluginName, builtinPlacement, schemas.Ptr(5))

	// 6. OTEL (if configured in PluginConfigs)
	otelConfig := s.getPluginConfig(otel.PluginName)
	if otelConfig != nil && otelConfig.Enabled {
		s.registerPluginWithStatus(ctx, otel.PluginName, nil, otelConfig.Config, false)
	} else {
		s.markPluginDisabled(otel.PluginName)
	}
	s.Config.SetPluginOrderInfo(otel.PluginName, builtinPlacement, schemas.Ptr(6))

	// 7. Semantic Cache (if configured in PluginConfigs)
	semanticCacheConfig := s.getPluginConfig(semanticcache.PluginName)
	if semanticCacheConfig != nil && semanticCacheConfig.Enabled {
		s.registerPluginWithStatus(ctx, semanticcache.PluginName, nil, semanticCacheConfig.Config, false)
	} else {
		s.markPluginDisabled(semanticcache.PluginName)
	}
	s.Config.SetPluginOrderInfo(semanticcache.PluginName, builtinPlacement, schemas.Ptr(7))

	// 8. Compat (if any compat feature is enabled in ClientConfig)
	cc := s.Config.ClientConfig.Compat
	compatCfg := &compat.Config{
		ConvertTextToChat:      cc.ConvertTextToChat,
		ConvertChatToResponses: cc.ConvertChatToResponses,
		ShouldDropParams:       cc.ShouldDropParams,
		ShouldConvertParams:    cc.ShouldConvertParams,
		AzureDeepseek:          cc.AzureDeepseek,
	}
	s.registerPluginWithStatus(ctx, compat.PluginName, nil, compatCfg, false)
	s.Config.SetPluginOrderInfo(compat.PluginName, builtinPlacement, schemas.Ptr(8))

	// 9. Maxim (if configured in PluginConfigs)
	maximConfig := s.getPluginConfig(maxim.PluginName)
	if maximConfig != nil && maximConfig.Enabled {
		s.registerPluginWithStatus(ctx, maxim.PluginName, nil, maximConfig.Config, false)
	} else {
		s.markPluginDisabled(maxim.PluginName)
	}
	s.Config.SetPluginOrderInfo(maxim.PluginName, builtinPlacement, schemas.Ptr(9))

	// 10. ModelCatalogResolver (last routing layer — fills req.Provider from catalog only when
	// no earlier routing plugin (governance routing rules, governance VK LB, enterprise LB)
	// already set one. CEL rules can still match on provider == "" because this runs last.
	// Requires a model catalog; only register when one is configured.
	if s.Config.ModelCatalog != nil {
		s.registerPluginWithStatus(ctx, modelcatalogresolver.PluginName, nil, nil, false)
	} else {
		s.markPluginDisabled(modelcatalogresolver.PluginName)
	}
	// Place it in post_builtin with a max order so it runs after every other routing plugin,
	// including post_builtin ones like the enterprise load balancer (which would otherwise run
	// after this builtin and never get a chance to pick the provider first).
	s.Config.SetPluginOrderInfo(modelcatalogresolver.PluginName, schemas.Ptr(schemas.PluginPlacementPostBuiltin), schemas.Ptr(math.MaxInt))

	// 11. AquaDoor PII egress guardrail (#1780 §7.5). Runs late (after compat) so it redacts the
	// fully-assembled request before egress; its runtime fail-closed (Presidio error/timeout → block)
	// lives in the plugin. Recognition is now IN-PROCESS (no external Presidio service), so the
	// guardrail is ON whenever the config block is enabled — there is no URL to wait for and no
	// incremental "boot before Presidio" gap. It cannot fail open (no network hop). Cutover (C2)
	// runs with it enabled; the C1.4 PII acceptance test enforces that.
	if piiConfig := s.getPluginConfig("aquadoor-pii"); piiConfig != nil && piiConfig.Enabled {
		s.registerPluginWithStatus(ctx, "aquadoor-pii", nil, piiConfig.Config, false)
	} else {
		s.markPluginDisabled("aquadoor-pii")
	}
	s.Config.SetPluginOrderInfo("aquadoor-pii", builtinPlacement, schemas.Ptr(10))

	// 12. AquaDoor OBO (#1780 §7.2). MUST run after governance (order 4) so the VK name (= user
	// email) is stamped in context before GovernanceVKNameResolver reads it. Self-configuring:
	// registers only when an issuer is set (so B1/B2 boot before the OBO actor key exists — B5).
	if oboConfig := s.getPluginConfig("aquadoor-obo"); oboConfig != nil && oboConfig.Enabled {
		if cfg, _ := MarshalPluginConfig[aquadoorobo.Config](oboConfig.Config); cfg != nil && cfg.Issuer != "" {
			s.registerPluginWithStatus(ctx, "aquadoor-obo", nil, oboConfig.Config, false)
		} else {
			s.markPluginDisabled("aquadoor-obo")
			logger.Warn("aquadoor-obo enabled but no Issuer — OBO is OFF (set AQUADOOR_OBO_ISSUER); MUST be configured before runner MCP calls")
		}
	} else {
		s.markPluginDisabled("aquadoor-obo")
	}
	s.Config.SetPluginOrderInfo("aquadoor-obo", builtinPlacement, schemas.Ptr(11))

	// 13. AquaDoor per-user LLM cost metering (#1814). HTTPTransportPreAuthHook — swaps a LibreChat-
	// vouched end-user email to that user's per-user VK BEFORE auth settles identity, so governance
	// meters cost/budget/rate PER USER. Ships DARK: registers only when the trusted-asserter VK env is
	// set AND a config store is present (email→VK resolution needs it) — so pre-cutover boots run
	// pure pass-through. As a PreAuth hook it runs before every PreRequest/PreLLM hook, so its order
	// relative to governance (4) is irrelevant to correctness; ordered last among builtins.
	if os.Getenv("AQUADOOR_USERMETER_ASSERTER_VK") != "" && s.Config.ConfigStore != nil {
		umPluginConfig := s.getPluginConfig("aquadoor-usermeter")
		var umCfg any
		if umPluginConfig != nil {
			umCfg = umPluginConfig.Config
		}
		s.registerPluginWithStatus(ctx, "aquadoor-usermeter", nil, umCfg, false)
	} else {
		s.markPluginDisabled("aquadoor-usermeter")
		logger.Info("aquadoor-usermeter disabled — set AQUADOOR_USERMETER_ASSERTER_VK (+ a config store) to enable per-user LLM cost metering")
	}
	s.Config.SetPluginOrderInfo("aquadoor-usermeter", builtinPlacement, schemas.Ptr(12))

	return nil
}

// loadCustomPlugins loads plugins from PluginConfigs
func (s *BifrostHTTPServer) loadCustomPlugins(ctx context.Context) error {
	for _, cfg := range s.Config.PluginConfigs {
		// Skip built-ins (already loaded)
		if lib.IsBuiltinPlugin(cfg.Name) {
			continue
		}
		// Handle disabled plugins
		if !cfg.Enabled {
			// For custom plugins with a path, verify to get the real plugin name
			if cfg.Path != nil {
				pluginName, err := s.Config.PluginLoader.VerifyBasePlugin(*cfg.Path)
				if err != nil {
					logger.Error("failed to verify disabled plugin %s: %v", cfg.Name, err)
					continue
				}
				// Store plugin status without instantiating (no Init() call, no resource usage)
				// Note: We can't determine types without instantiating, so pass empty slice
				s.Config.UpdatePluginOverallStatus(pluginName, cfg.Name, schemas.PluginStatusDisabled,
					[]string{fmt.Sprintf("plugin %s is disabled", cfg.Name)}, []schemas.PluginType{})
			} else {
				// Built-in plugin - use cfg.Name directly
				s.Config.UpdatePluginOverallStatus(cfg.Name, cfg.Name, schemas.PluginStatusDisabled,
					[]string{fmt.Sprintf("plugin %s is disabled", cfg.Name)}, []schemas.PluginType{})
			}
			continue
		}

		// Plugin is enabled - instantiate it
		plugin, err := InstantiatePlugin(ctx, cfg.Name, cfg.Path, cfg.Config, s.Config)
		if err != nil {
			// Skip enterprise plugins silently
			if slices.Contains(enterprisePlugins, cfg.Name) {
				continue
			}
			logger.Error("failed to load plugin %s: %v", cfg.Name, err)
			// Use cfg.Name since plugin may be nil when InstantiatePlugin returns an error
			s.Config.UpdatePluginOverallStatus(cfg.Name, cfg.Name, schemas.PluginStatusError,
				[]string{fmt.Sprintf("error loading plugin %s: %v", cfg.Name, err)}, []schemas.PluginType{})
			continue
		}

		// Ensure plugin is not nil before using it (defensive check)
		if plugin == nil {
			logger.Error("plugin %s instantiated but returned nil", cfg.Name)
			s.Config.UpdatePluginOverallStatus(cfg.Name, cfg.Name, schemas.PluginStatusError,
				[]string{fmt.Sprintf("plugin %s instantiated but returned nil", cfg.Name)}, []schemas.PluginType{})
			continue
		}

		// Register enabled plugin and mark as active
		s.Config.ReloadPlugin(plugin)
		s.Config.SetPluginOrderInfo(plugin.GetName(), cfg.Placement, cfg.Order)
		s.Config.UpdatePluginOverallStatus(plugin.GetName(), cfg.Name, schemas.PluginStatusActive,
			[]string{fmt.Sprintf("plugin %s initialized successfully", cfg.Name)}, InferPluginTypes(plugin))
	}
	return nil
}
