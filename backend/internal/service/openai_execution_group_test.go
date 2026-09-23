package service

import (
	"context"
	"testing"
)

type piExecutionAccountRepo struct {
	AccountRepository
	members []Account
}

func (r piExecutionAccountRepo) ListByGroup(_ context.Context, _ int64) ([]Account, error) {
	return r.members, nil
}

type piExecutionGroupRepo struct {
	GroupRepository
	group Group
}

type piExecutionUserRepo struct {
	UserRepository
	owner User
}

func (r piExecutionUserRepo) GetByID(_ context.Context, _ int64) (*User, error) {
	return &r.owner, nil
}

func (r piExecutionGroupRepo) GetByID(_ context.Context, _ int64) (*Group, error) {
	return &r.group, nil
}

func TestOpenAIExecutionGroupsShareBusinessBindings(t *testing.T) {
	pi := &Account{Platform: PlatformOpenAI, Type: AccountTypeOAuth, Credentials: map[string]any{"harness_kind": "pi", "pi_owner_user_id": "7"}}
	cpa := &Account{Platform: PlatformOpenAI, Type: AccountTypeAPIKey}
	for _, tc := range []struct {
		name      string
		candidate *Account
		members   []Account
		groups    []int64
		wantError bool
	}{
		{name: "Pi requires a chosen group", candidate: pi, wantError: true},
		{name: "Pi may join CPA", candidate: pi, members: []Account{{ID: 2, Platform: PlatformOpenAI, Type: AccountTypeAPIKey}}, groups: []int64{1}},
		{name: "CPA may join Pi", candidate: cpa, members: []Account{{ID: 3, Platform: PlatformOpenAI, Type: AccountTypeOAuth, Credentials: map[string]any{"harness_kind": "pi"}}}, groups: []int64{1}},
		{name: "Pi may share a dedicated Pi group", candidate: pi, members: []Account{{ID: 3, Platform: PlatformOpenAI, Type: AccountTypeOAuth, Credentials: map[string]any{"harness_kind": "pi"}}}, groups: []int64{1}},
		{name: "CPA may share a CPA group", candidate: cpa, members: []Account{{ID: 2, Platform: PlatformOpenAI, Type: AccountTypeAPIKey}}, groups: []int64{1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc := &adminServiceImpl{
				accountRepo: piExecutionAccountRepo{members: tc.members},
				groupRepo:   piExecutionGroupRepo{group: Group{ID: 1, Platform: PlatformOpenAI, Status: StatusActive, IsExclusive: true}},
				userRepo:    piExecutionUserRepo{owner: User{ID: 7, Status: StatusActive, AllowedGroups: []int64{1}}},
			}
			err := svc.validateOpenAIExecutionGroups(context.Background(), tc.candidate, 0, tc.groups)
			if (err != nil) != tc.wantError {
				t.Fatalf("error = %v, wantError = %t", err, tc.wantError)
			}
		})
	}
}

func TestPiExecutionAccountAllowsPublicOpenAIGroup(t *testing.T) {
	pi := &Account{Platform: PlatformOpenAI, Type: AccountTypeOAuth, Credentials: map[string]any{"harness_kind": "pi", "pi_owner_user_id": "7"}}
	svc := &adminServiceImpl{accountRepo: piExecutionAccountRepo{}, groupRepo: piExecutionGroupRepo{group: Group{ID: 1, Platform: PlatformOpenAI, Status: StatusActive}}, userRepo: piExecutionUserRepo{owner: User{ID: 7, Status: StatusActive, AllowedGroups: []int64{1}}}}
	if err := svc.validateOpenAIExecutionGroups(context.Background(), pi, 0, []int64{1}); err != nil {
		t.Fatalf("Pi account rejected a public group: %v", err)
	}
}

func TestPiAccountRequiresSeparateCredentialBinding(t *testing.T) {
	account := &Account{Platform: PlatformOpenAI, Type: AccountTypeOAuth, Credentials: map[string]any{
		"harness_kind": "pi", "pi_owner_user_id": "42", "chatgpt_account_id": "account-a",
		"access_token": "fixture-access", "refresh_token": "fixture-refresh",
	}}
	if err := ValidateExecutionAccount(account); err != nil {
		t.Fatalf("valid Pi account rejected: %v", err)
	}
	account.Credentials["base_url"] = "http://cpa:8317"
	if err := ValidateExecutionAccount(account); err == nil {
		t.Fatal("Pi account accepted a CPA destination")
	}
	delete(account.Credentials, "base_url")
	delete(account.Credentials, "refresh_token")
	if err := ValidateExecutionAccount(account); err == nil {
		t.Fatal("Pi account accepted a missing refresh binding")
	}
}
