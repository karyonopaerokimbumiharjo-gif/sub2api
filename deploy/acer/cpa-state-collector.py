#!/usr/bin/env python3
"""Keep credential-bound 292 states fresh; read the existing Sub2API admin toggle."""
import argparse, base64, concurrent.futures, hashlib, json, os, pathlib, subprocess, threading, time, urllib.request, urllib.error

from state_slots import maintain, offer, needs_probe, feedback

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--root', required=True)
    args = parser.parse_args()
    root = pathlib.Path(args.root)
    private = root / 'private'
    state_file = private / 'managed-state' / 'states.json'
    state_file.parent.mkdir(mode=0o700, exist_ok=True)
    meta = {x['Name'].lstrip('/'): x for x in json.loads((private / 'containers.json').read_text())}
    db_env = dict(x.split('=', 1) for x in meta['sub2api-postgres']['Config']['Env'] if '=' in x)
    secret = (private / 'cpa/management-password').read_text().strip()
    models = ['gpt-6-astra', 'gpt-5.6-sol', 'gpt-5.6-terra']
    lock = threading.Lock()
    entries, pending, retry, blocked, failures = {}, set(), {}, set(), {}
    enabled = False
    allowed_keys, generation, strikes = set(), 0, {}
    events = []
    standbys = {}
    try:
        previous = json.loads(state_file.read_text())
        entries = {k:v for k,v in previous.get('entries',{}).items() if v.get('expires_at',0)>time.time() and len(v.get('state',''))==292}
        events = previous.get('events',[])[-100:]
        standbys = previous.get('standbys',{})
        maintain(entries, standbys, time.time())
    except (OSError, ValueError, TypeError):
        pass
    routes = json.loads((private / 'state-pool/config.json').read_text())['proxy_urls']
    assert routes and all(x.startswith('http://egress:') for x in routes)
    pool = concurrent.futures.ThreadPoolExecutor(max_workers=2)

    def call(path, data=None):
        inspect = json.loads(subprocess.check_output(['docker','inspect','acer-sub2api-cpa']))[0]
        ip = next(v['IPAddress'] for v in inspect['NetworkSettings']['Networks'].values())
        request = urllib.request.Request('http://' + ip + ':8317' + path,
            data=json.dumps(data).encode() if data is not None else None,
            headers={'Authorization':'Bearer ' + secret,'Content-Type':'application/json'})
        with urllib.request.urlopen(request, timeout=65) as response:
            return json.load(response)

    def probe(auth, model, route, epoch):
        key = auth['auth_index'] + '\0' + model
        try:
            account = (auth.get('id_token') or {}).get('chatgpt_account_id')
            if not account:
                return
            headers = {'Authorization':'Bearer $TOKEN$', 'ChatGPT-Account-Id':account,
                'Content-Type':'application/json', 'Accept':'text/event-stream',
                'OpenAI-Beta':'responses=experimental','originator':'codex-tui',
                'version':'0.154.0','User-Agent':'codex-tui/0.154.0'}
            payload = {'model':model,'stream':True,'store':False,'instructions':'Reply exactly pong.',
                'input':[{'role':'user','content':[{'type':'input_text','text':'ping'}]}]}
            response = call('/v0/management/api-call', {'auth_index':auth['auth_index'],
                'method':'POST','url':'https://chatgpt.com/backend-api/codex/responses',
                'proxy_url':route,'header':headers,'data':json.dumps(payload)})
            code = response.get('status_code')
            state = next((v for k,v in response.get('header',{}).items() if k.lower() == 'x-codex-turn-state'), [])
            state = state[0] if isinstance(state,list) and state else ''
            terminal = False
            actual_model = ""
            mismatch = False
            for line in response.get('body','').splitlines():
                if line.startswith('data:'):
                    try:
                        event = json.loads(line[5:].strip())
                        observed = (event.get('response') or {}).get('model') or event.get('model')
                        if observed:
                            actual_model = observed
                            mismatch = mismatch or observed != model
                        if event.get('type') == 'response.completed': terminal = True
                        if event.get('type') in ('response.failed','response.incomplete','error'): terminal = False; break
                    except (ValueError,TypeError): pass
            print(json.dumps({'event':'probe_result','model':model,'status':code,'length':len(state),'completed':terminal}),flush=True)
            with lock:
                if epoch != generation or not enabled or key not in allowed_keys: return
                if code in (401,403,429): retry[key] = time.time()+300
                events.append({'time':int(time.time()),'model':model,'length':len(state),'status':code,'completed':terminal,'accepted':False,'actual_model':actual_model,'reason':'model_mismatch' if mismatch else ''})
                del events[:-100]
                event = events[-1]
            if code != 200 or not terminal or mismatch or actual_model != model or len(state) != 292:
                return
            decoded = base64.urlsafe_b64decode(state)
            now = int(time.time())
            issued = int.from_bytes(decoded[1:9], 'big')
            if len(decoded) != 217 or decoded[0] != 128 or not now-3600 < issued <= now+5:
                return
            with lock:
                if epoch != generation or not enabled or key not in allowed_keys: return
                event['accepted'] = True
                offer(entries, standbys, key, {'state':state,'expires_at':min(issued+3600, now+3600)}, now)
            print(json.dumps({'event':'state_ready','identity':hashlib.sha256(auth['auth_index'].encode()).hexdigest()[:12], 'model':model,'length':292}),flush=True)
        except Exception as error:
            print(json.dumps({'event':'probe_failed','type':type(error).__name__}),flush=True)
        finally:
            with lock:
                pending.discard(key)
                if not needs_probe(entries, standbys, key, time.time()):
                    failures[key] = 0
                    retry[key] = time.time()+180
                else:
                    failures[key] = failures.get(key,0)+1
                    retry[key] = max(retry.get(key,0),time.time()+(180 if failures[key] % 13 == 0 else 6))

    auths, last_discovery, route_index = [], 0, 0
    while True:
        now = int(time.time())
        try:
            result = subprocess.run(['docker','exec','acer-sub2api-postgres','psql','-U',db_env['POSTGRES_USER'],
                '-d',db_env['POSTGRES_DB'],'-Atc',"SELECT value FROM settings WHERE key='openai_codex_ticket_enabled'"],
                capture_output=True,text=True,timeout=5,check=True)
            next_enabled = result.stdout.strip() == 'true'
            selected = subprocess.check_output(['docker','exec','acer-sub2api-postgres','psql','-U',db_env['POSTGRES_USER'],'-d',db_env['POSTGRES_DB'],'-Atc',"SELECT value FROM settings WHERE key='openai_codex_ticket_models'"],timeout=5,text=True).strip()
            models = json.loads(selected) if selected else ['gpt-6-astra', 'gpt-5.6-sol', 'gpt-5.6-terra']
            if not isinstance(models, list) or any(m not in ['gpt-6-astra', 'gpt-5.6-sol', 'gpt-5.6-terra'] for m in models):
                raise ValueError('Invalid collection models')
            models = list(dict.fromkeys(models))
            if now-last_discovery >= 5:
                auths = call('/v0/management/auth-files').get('files',[])
                last_discovery = now
            binding_query = "SELECT COALESCE(json_agg(extra->>'cpa_auth_id'), '[]'::json) FROM accounts WHERE deleted_at IS NULL AND status='active' AND schedulable AND extra ? 'cpa_identity'"
            bindings = subprocess.check_output(['docker','exec','acer-sub2api-postgres','psql','-U',db_env['POSTGRES_USER'],'-d',db_env['POSTGRES_DB'],'-Atc',binding_query],timeout=5,text=True)
            enabled_ids = set(json.loads(bindings))
            live = [a for a in auths if a.get('id') in enabled_ids and not a.get('disabled') and a.get('auth_index') and (a.get('id_token') or {}).get('chatgpt_account_id')]
            keys = {a['auth_index']+'\0'+m for a in live for m in models} if next_enabled else set()
            with lock:
                if keys != allowed_keys or enabled != next_enabled: generation += 1
                allowed_keys, enabled = keys, next_enabled
                for slots in (entries,standbys,retry,failures,strikes):
                    for key in list(slots):
                        if key not in keys: slots.pop(key,None)
                maintain(entries, standbys, now)
                lookup = {hashlib.sha256(k.encode()).hexdigest(): k for k in keys}
                for report in (private/'state-feedback').glob('*.json'):
                    try:
                        f = json.loads(report.read_text())
                        key = lookup.get(f.get('key'))
                        if key and now-120 <= f.get('time',0) <= now+5:
                            action = feedback(entries,standbys,key,f.get('state_hash'),now,f.get('reason'),strikes)
                            if action != 'stale_feedback_ignored': retry[key] = 0
                            events.append({'time':now,'model':f.get('model',''),'actual_model':f.get('actual_model',''),'length':0,'status':f.get('status',0),'accepted':False,'reason':f.get('reason',''),'action':action})
                    except (OSError,ValueError,TypeError): pass
                    finally: report.unlink(missing_ok=True)
                del events[:-100]
                snapshot = {'enabled':enabled,'updated_at':now,'models':models,'entries':dict(entries), 'events':[dict(e) for e in events], 'standbys':dict(standbys), 'ttl_seconds':3600,'refresh_before_seconds':600,'eligible_accounts':len(live),'collecting':len(pending)}
            tmp = state_file.with_suffix('.tmp')
            with os.fdopen(os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600),'w') as output:
                json.dump(snapshot,output)
            os.replace(tmp,state_file)
            if enabled:
                for auth in live:
                    for model in models:
                        key = auth['auth_index']+'\0'+model
                        with lock:
                            if len(pending)>=2 or key in pending or retry.get(key,0)>now or not needs_probe(entries,standbys,key,now): continue
                            pending.add(key)
                        pool.submit(probe,auth,model,routes[route_index % len(routes)],generation)
                        route_index += 1
        except Exception as error:
            # Stop the heartbeat so the executor fails closed after 30 seconds.
            print(json.dumps({'event':'controller_failed','type':type(error).__name__}),flush=True)
        time.sleep(5)

if __name__ == '__main__': main()
