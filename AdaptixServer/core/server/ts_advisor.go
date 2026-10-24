package server

import (
	"encoding/json"
	"net/http"

	"AdaptixServer/core/advisor"
	"AdaptixServer/core/utils/logs"

	"github.com/Adaptix-Framework/axc2"
)

func (ts *Teamserver) GetAgent(agentId string) (adaptix.AgentData, bool) {
	value, ok := ts.Agents.Get(agentId)
	if !ok {
		return adaptix.AgentData{}, false
	}
	agent, ok := value.(*Agent)
	if !ok {
		return adaptix.AgentData{}, false
	}
	return agent.GetData(), true
}

func (ts *Teamserver) GetAllAgents() []adaptix.AgentData {
	var agents []adaptix.AgentData
	ts.Agents.ForEach(func(key string, value interface{}) bool {
		agent, ok := value.(*Agent)
		if ok {
			agents = append(agents, agent.GetData())
		}
		return true
	})
	return agents
}

func (ts *Teamserver) SyncAdvisor(packet interface{}) {
	ts.TsSyncAllClients(packet)
}

func (ts *Teamserver) InitAdvisor() {
	if ts.Profile.Advisor == nil {
		return
	}

	config := advisor.AdvisorConfig{
		Enabled:      ts.Profile.Advisor.Enabled,
		Provider:     ts.Profile.Advisor.Provider,
		ApiKey:       ts.Profile.Advisor.ApiKey,
		Model:        ts.Profile.Advisor.Model,
		Scope:        ts.Profile.Advisor.Scope,
		Endpoint:     ts.Profile.Advisor.Endpoint,
		MaxHistory:   ts.Profile.Advisor.MaxHistory,
		RedactCreds:  ts.Profile.Advisor.RedactCreds,
		MaxOutputLen: ts.Profile.Advisor.MaxOutputLen,
		BofPath:      ts.Profile.Advisor.BofPath,
	}

	ts.Advisor = advisor.NewAdvisor(config, ts)
	ts.Advisor.RegisterHooks(ts.EventManager)

	if config.Enabled {
		ts.initAdvisorEndpoints()
	}
}

func (ts *Teamserver) initAdvisorEndpoints() {
	err := ts.TsEndpointRegister("POST", "/advisor/chat", func(username string, body []byte) (int, []byte) {
		var req advisor.ChatRequest
		if err := json.Unmarshal(body, &req); err != nil {
			resp, _ := json.Marshal(map[string]string{"error": "invalid request body"})
			return http.StatusBadRequest, resp
		}

		if req.AgentID == "" || req.Message == "" {
			resp, _ := json.Marshal(map[string]string{"error": "agent_id and message are required"})
			return http.StatusBadRequest, resp
		}

		go ts.Advisor.HandleChat(req.AgentID, req.Message)

		resp, _ := json.Marshal(map[string]string{"status": "ok"})
		return http.StatusOK, resp
	})
	if err != nil {
		logs.Warn("", "AI Advisor: failed to register /advisor/chat endpoint: %v", err)
	}
}
