package advisor

import (
	"sync"
	"time"
)

type ChatMessage struct {
	Timestamp time.Time
	Role      string // "operator" or "advisor"
	Message   string
}

type AgentState struct {
	mu                sync.RWMutex
	Context           AgentContext
	History           []HistoryEntry
	maxHist           int
	Recon             *ReconState
	EngagementSummary string
	ChatMessages      []ChatMessage
	maxChat           int
}

func NewAgentState(ctx AgentContext, maxHistory int) *AgentState {
	if maxHistory <= 0 {
		maxHistory = 10
	}
	return &AgentState{
		Context:      ctx,
		History:      make([]HistoryEntry, 0, maxHistory),
		maxHist:      maxHistory,
		Recon:        NewReconState(),
		ChatMessages: make([]ChatMessage, 0, 20),
		maxChat:      20,
	}
}

func (s *AgentState) AddHistory(entry HistoryEntry) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.History = append(s.History, entry)
	if len(s.History) > s.maxHist {
		s.History = s.History[len(s.History)-s.maxHist:]
	}
}

func (s *AgentState) GetHistory() []HistoryEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]HistoryEntry, len(s.History))
	copy(out, s.History)
	return out
}

func (s *AgentState) UpdateContext(ctx AgentContext) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Context = ctx
}

func (s *AgentState) GetContext() AgentContext {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.Context
}

func (s *AgentState) SetEngagementSummary(summary string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.EngagementSummary = summary
}

func (s *AgentState) GetEngagementSummary() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.EngagementSummary
}

func (s *AgentState) AddChatMessage(role, message string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.ChatMessages = append(s.ChatMessages, ChatMessage{
		Timestamp: time.Now().UTC(),
		Role:      role,
		Message:   message,
	})
	if len(s.ChatMessages) > s.maxChat {
		s.ChatMessages = s.ChatMessages[len(s.ChatMessages)-s.maxChat:]
	}
}

func (s *AgentState) GetChatMessages() []ChatMessage {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]ChatMessage, len(s.ChatMessages))
	copy(out, s.ChatMessages)
	return out
}
