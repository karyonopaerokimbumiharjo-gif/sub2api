import { flushPromises, mount } from '@vue/test-utils'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import type { AdminUser } from '@/types'
import UserEditModal from '../UserEditModal.vue'

const { updateUser, showSuccess } = vi.hoisted(() => ({
  updateUser: vi.fn(),
  showSuccess: vi.fn()
}))

vi.mock('@/api/admin', () => ({
  adminAPI: {
    users: { update: updateUser },
    userAttributes: { updateUserAttributeValues: vi.fn() }
  }
}))

vi.mock('@/stores/app', () => ({
  useAppStore: () => ({ showSuccess, showError: vi.fn() })
}))

vi.mock('@/composables/useClipboard', () => ({
  useClipboard: () => ({ copyToClipboard: vi.fn() })
}))

vi.mock('@/composables/useStepUp', () => ({
  useStepUp: () => ({ run: (operation: () => Promise<unknown>) => operation() }),
  isStepUpBlocked: () => false,
  isStepUpCancelled: () => false,
  stepUpBlockReason: () => ''
}))

vi.mock('vue-i18n', async () => {
  const actual = await vi.importActual<typeof import('vue-i18n')>('vue-i18n')
  return { ...actual, useI18n: () => ({ t: (key: string) => key }) }
})

const user: AdminUser = {
  id: 42,
  username: 'trusted',
  email: 'trusted@example.test',
  role: 'user',
  balance: 0,
  concurrency: 1,
  status: 'active',
  allowed_groups: [],
  balance_notify_enabled: false,
  balance_notify_threshold: null,
  balance_notify_extra_emails: [],
  created_at: '2026-08-11T00:00:00Z',
  updated_at: '2026-08-11T00:00:00Z',
  notes: '',
  prompt_audit_bypass: true
}

describe('UserEditModal prompt audit bypass', () => {
  beforeEach(() => {
    updateUser.mockReset().mockResolvedValue(user)
    showSuccess.mockReset()
  })

  it('loads and saves the per-user security audit release switch', async () => {
    const wrapper = mount(UserEditModal, {
      props: { show: true, user },
      global: {
        stubs: {
          BaseDialog: { props: ['show'], template: '<div v-if="show"><slot /><slot name="footer" /></div>' },
          UserAttributeForm: true,
          Icon: true,
          TotpStepUpDialog: true
        }
      }
    })

    const toggle = wrapper.get<HTMLInputElement>('[data-test="prompt-audit-bypass"]')
    expect(toggle.element.checked).toBe(true)
    await toggle.setValue(false)
    await wrapper.get('form').trigger('submit')
    await flushPromises()

    expect(updateUser).toHaveBeenCalledWith(42, expect.objectContaining({ prompt_audit_bypass: false }))
  })
})
