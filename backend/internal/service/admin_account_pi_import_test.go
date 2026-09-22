package service

import (
	"context"
	"errors"
	"testing"

	"github.com/imroc/req/v3"
)

type piAtomicCreateRepo struct {
	AccountRepository
	atomicCalled bool
	legacyCalled bool
	err          error
	bindings     []AccountGroup
}

func (r *piAtomicCreateRepo) ListByGroup(context.Context, int64) ([]Account, error) { return nil, nil }
func (r *piAtomicCreateRepo) CreateWithAccountGroups(_ context.Context, account *Account, bindings []AccountGroup) error {
	r.atomicCalled = true
	r.bindings = bindings
	if r.err != nil {
		return r.err
	}
	account.ID = 91
	return nil
}
func (r *piAtomicCreateRepo) Create(context.Context, *Account) error {
	r.legacyCalled = true
	return errors.New("legacy create must not run")
}
func (r *piAtomicCreateRepo) BindGroups(context.Context, int64, []int64) error {
	r.legacyCalled = true
	return errors.New("legacy bind must not run")
}

func TestBuildAccountForPiImportStartsDisabledAndUnschedulable(t *testing.T) {
	account, err := buildAccountForCreate(&CreateAccountInput{
		Name: "Pi", Platform: PlatformOpenAI, Type: AccountTypeOAuth,
		InitiallyDisabled: true, InitiallyUnschedulable: true,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if account.Status != StatusDisabled || account.Schedulable {
		t.Fatalf("Pi import may dispatch before approval: status=%s schedulable=%v", account.Status, account.Schedulable)
	}
}

func TestPiAccountSkipsDirectOpenAIPrivacyCalls(t *testing.T) {
	called := false
	account := &Account{
		Platform: PlatformOpenAI, Type: AccountTypeOAuth,
		Credentials: map[string]any{"harness_kind": "pi", "access_token": "fixture-access"},
	}
	svc := &adminServiceImpl{privacyClientFactory: func(string) (*req.Client, error) {
		called = true
		return nil, errors.New("Pi must not call direct upstream privacy API")
	}}
	if result := svc.EnsureOpenAIPrivacy(context.Background(), account); result != "" {
		t.Fatalf("unexpected Pi privacy result %q", result)
	}
	if result := svc.ForceOpenAIPrivacy(context.Background(), account); result != "" {
		t.Fatalf("unexpected forced Pi privacy result %q", result)
	}
	if called {
		t.Fatal("Pi credential made a direct upstream privacy call")
	}
}

func TestCreatePiAccountUsesAtomicAccountGroupPersistence(t *testing.T) {
	for _, fail := range []bool{false, true} {
		repo := &piAtomicCreateRepo{}
		if fail {
			repo.err = errors.New("group binding transaction failed")
		}
		svc := &adminServiceImpl{
			accountRepo:          repo,
			accountDuplicateRepo: repo,
			groupRepo:            piExecutionGroupRepo{group: Group{ID: 42, Platform: PlatformOpenAI, Status: StatusActive, IsExclusive: true}},
			userRepo:             piExecutionUserRepo{owner: User{ID: 7, Status: StatusActive, AllowedGroups: []int64{42}}},
		}
		account, err := svc.CreateAccount(context.Background(), &CreateAccountInput{
			Name: "Pi OpenAI", Platform: PlatformOpenAI, Type: AccountTypeOAuth,
			Credentials: map[string]any{"harness_kind": "pi", "pi_owner_user_id": "7", "chatgpt_account_id": "fixture-account", "access_token": "fixture-access", "refresh_token": "fixture-refresh"},
			GroupIDs:    []int64{42}, SkipDefaultGroupBind: true, InitiallyDisabled: true, InitiallyUnschedulable: true,
		})
		if !repo.atomicCalled || repo.legacyCalled || len(repo.bindings) != 1 || repo.bindings[0].GroupID != 42 {
			t.Fatalf("Pi creation bypassed atomic persistence: %+v", repo)
		}
		if fail {
			if !errors.Is(err, repo.err) || account != nil {
				t.Fatalf("failed atomic transaction returned account=%v err=%v", account, err)
			}
		} else if err != nil || account == nil || account.Status != StatusDisabled || account.Schedulable {
			t.Fatalf("unsafe Pi creation: account=%v err=%v", account, err)
		}
	}
}
