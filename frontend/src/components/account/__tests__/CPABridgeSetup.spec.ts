import {mount,flushPromises} from '@vue/test-utils'
import {beforeEach,describe,it,expect,vi} from 'vitest'
const mocks=vi.hoisted(()=>({get:vi.fn(),save:vi.fn()}))
vi.mock('@/api/admin/accounts',()=>({getCPABridgeOptions:mocks.get,ensureCPAQuotaBridge:mocks.save}))
vi.mock('vue-i18n',()=>({useI18n:()=>({locale:{value:'zh'}})}))
import CPABridgeSetup from '../CPABridgeSetup.vue'
const data=()=>({bridge:null,groups:[{id:2,name:'pro'}],candidates:[{name:'ready.json',email:'ready@example.invalid',provider:'codex',status:'active',can_bridge:true,reason:''},{name:'disabled.json',email:'disabled@example.invalid',provider:'codex',status:'disabled',can_bridge:false,reason:'已停用'}]})
describe('CPA bridge selection',()=>{
 beforeEach(()=>{vi.resetAllMocks();mocks.get.mockResolvedValue(data());mocks.save.mockResolvedValue({created:true,account_id:32,email:'ready@example.invalid',groups_configured:true})})
 it('shows pool identities and disabled reasons without silently choosing an account',async()=>{const w=mount(CPABridgeSetup,{props:{show:true}});await flushPromises();expect(w.text()).toContain('ready@example.invalid');expect(w.text()).toContain('已停用');expect(w.get('input[value="disabled.json"]').attributes('disabled')).toBeDefined();expect(w.get('[data-testid="cpa-save-bridge"]').attributes('disabled')).toBeDefined();expect(mocks.save).not.toHaveBeenCalled()})
 it('requires a group and submits the exact selection',async()=>{const w=mount(CPABridgeSetup,{props:{show:true}});await flushPromises();await w.get('input[value="ready.json"]').setValue();expect(w.get('[data-testid="cpa-save-bridge"]').attributes('disabled')).toBeDefined();await w.get('input[name="bridge-group"]').setValue(true);await w.get('[data-testid="cpa-save-bridge"]').trigger('click');await flushPromises();expect(mocks.save).toHaveBeenCalledWith('ready.json',[2]);expect(w.emitted('updated')).toHaveLength(1);expect(w.get('[role="status"]').text()).toContain('32')})
 it('shows the existing binding and preserves its groups',async()=>{mocks.get.mockResolvedValue({...data(),bridge:{account_id:32,auth_name:'ready.json',email:'ready@example.invalid',group_ids:[2]}});const w=mount(CPABridgeSetup,{props:{show:true}});await flushPromises();expect(w.get('[data-testid="cpa-current-bridge"]').text()).toContain('32');await w.get('[data-testid="cpa-save-bridge"]').trigger('click');await flushPromises();expect(mocks.save).toHaveBeenCalledWith('ready.json',[2])})
 it('handles failed listing and failed saving without false success',async()=>{mocks.get.mockRejectedValueOnce(new Error('list failed'));const w=mount(CPABridgeSetup,{props:{show:true}});await flushPromises();expect(w.find('[role="alert"]').exists()).toBe(true);expect(mocks.save).not.toHaveBeenCalled()})
 it('refreshes candidates after a new import',async()=>{const w=mount(CPABridgeSetup,{props:{show:true,refreshKey:0}});await flushPromises();await w.setProps({refreshKey:1});await flushPromises();expect(mocks.get).toHaveBeenCalledTimes(2)})
})
