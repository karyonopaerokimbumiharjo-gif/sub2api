package service

import (
    "net/http"
    "testing"
)

func TestBasisPointsHeaderIsAccountControlled(t *testing.T) {
    a := &Account{Platform:PlatformOpenAI, Type:AccountTypeAPIKey, Credentials:map[string]any{"base_url":"http://cpa:8317"}, Extra:map[string]any{"cpa_auth_id":"bound",BasisPointsEnabledExtraKey:true}}
    if err:=ValidateCPAAccount(a); err!=nil { t.Fatal(err) }
    h:=http.Header{"x-sub2api-basispoints":[]string{"spoof"},"x-sub2api-cpa-auth-id":[]string{"other"}}
    a.ApplyHeaderOverrides(h)
    if h.Get(BasisPointsHeader)!="1" || h.Get("X-Sub2API-CPA-Auth-ID")!="bound" { t.Fatal("account routing missing") }
    a.Extra[BasisPointsEnabledExtraKey]=false
    a.ApplyHeaderOverrides(h)
    if h.Get(BasisPointsHeader)!="" { t.Fatal("disabled flag leaked") }
    a.Extra[BasisPointsEnabledExtraKey]="true"
    if validateBasisPointsExtra(a,a.Extra)==nil { t.Fatal("non boolean accepted") }
    a.Extra[BasisPointsEnabledExtraKey]=true
    delete(a.Extra,"cpa_auth_id")
    if validateBasisPointsExtra(a,a.Extra)==nil { t.Fatal("unbound account accepted") }
    a.ApplyHeaderOverrides(h)
    if h.Get(BasisPointsHeader)!="" { t.Fatal("unbound account routed") }
}
