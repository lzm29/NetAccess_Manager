for (const toggle of document.querySelectorAll('.password-toggle')) {
  const password = document.getElementById(toggle.getAttribute('aria-controls'));
  const label = toggle.dataset.passwordLabel;
  toggle.addEventListener('click', () => {
    const showPassword = password.type === 'password';
    password.type = showPassword ? 'text' : 'password';
    toggle.setAttribute('aria-label', (showPassword ? 'Ẩn ' : 'Hiện ') + label);
  });
  toggle.hidden = false;
}

const accountMenu = document.getElementById('account-menu');
if (accountMenu) {
  document.addEventListener('click', event => {
    if (!accountMenu.contains(event.target)) accountMenu.open = false;
  });
  accountMenu.addEventListener('focusout', event => {
    if (event.relatedTarget && !accountMenu.contains(event.relatedTarget)) accountMenu.open = false;
  });
  accountMenu.addEventListener('keydown', event => {
    if (event.key === 'Escape' && accountMenu.open) {
      event.preventDefault();
      accountMenu.open = false;
      accountMenu.querySelector('summary').focus();
    }
  });
}

for (const form of document.querySelectorAll('form[data-password-confirmation]')) {
  const password = form.elements[form.dataset.passwordConfirmation];
  const confirmation = form.elements.confirm_password;
  form.addEventListener('input', () => confirmation.setCustomValidity(''));
  form.addEventListener('submit', event => {
    if (password.value !== confirmation.value) {
      event.preventDefault();
      confirmation.setCustomValidity('Mật khẩu nhập lại chưa khớp.');
      confirmation.reportValidity();
    }
  });
  form.querySelector('[aria-invalid="true"]')?.focus();
}

const proposal = document.getElementById('proposal-form');
if (proposal) {
  const { list_type: list, change_action: action, target_type: type, target_value: target,
    description, conflict_ack: conflictAck } = proposal.elements;
  const descriptionGroup = document.getElementById('description-group');
  const descriptionLabel = descriptionGroup.querySelector('label');
  const targetHint = document.getElementById('target-hint');
  const summary = document.getElementById('proposal-error-summary');
  const targetCheck = document.getElementById('proposal-target-check');
  const conflictGroup = document.getElementById('proposal-conflict-group');
  const submit = proposal.querySelector('button[type="submit"]');
  let checkTimer;
  let checkRequest;

  function syncDescription() {
    const remove = action.value === 'REMOVE';
    descriptionGroup.hidden = remove;
    description.required = !remove;
    description.disabled = remove;
    descriptionLabel.textContent = action.value === 'UPDATE' ? 'Mô tả mới' : 'Mô tả quy tắc';
  }

  function syncTargetHint() {
    const option = type.selectedOptions[0];
    target.placeholder = option?.dataset.example || '';
    targetHint.textContent = option?.dataset.hint || '';
  }

  function clearError(field) {
    const error = document.getElementById(field.id + '-error');
    if (!error) return;
    error.remove();
    field.removeAttribute('aria-invalid');
    const descriptions = (field.getAttribute('aria-describedby') || '').split(' ')
      .filter(id => id && id !== error.id);
    if (descriptions.length) {
      field.setAttribute('aria-describedby', descriptions.join(' '));
    } else {
      field.removeAttribute('aria-describedby');
    }
  }

  function syncCheckControls(result) {
    const blocked = result?.hasAttribute('data-blocked');
    submit.disabled = Boolean(blocked);
    conflictGroup.hidden = blocked || !result?.hasAttribute('data-conflict');
  }

  function scheduleTargetCheck() {
    clearTimeout(checkTimer);
    checkRequest?.abort();
    conflictAck.checked = false;
    const value = target.value.trim();
    if (!value || !type.value || !list.value || !action.value) {
      targetCheck.hidden = true;
      targetCheck.textContent = '';
      syncCheckControls(null);
      return;
    }

    targetCheck.hidden = false;
    targetCheck.textContent = 'Đang tra cứu đích…';
    conflictGroup.hidden = true;
    submit.disabled = true;
    const controller = new AbortController();
    checkRequest = controller;
    const query = new URLSearchParams({
      target_type: type.value, target_value: value, list_type: list.value, change_action: action.value,
    });
    checkTimer = setTimeout(async () => {
      try {
        const response = await fetch(targetCheck.dataset.url + '?' + query, { signal: controller.signal });
        if (!response.ok || response.redirected) throw new Error('Tra cứu đích thất bại.');
        const html = await response.text();
        if (controller.signal.aborted) return;
        targetCheck.innerHTML = html;
        syncCheckControls(targetCheck.querySelector('[data-target-result]'));
      } catch (error) {
        if (controller.signal.aborted) return;
        targetCheck.textContent = 'Chưa tra cứu được. Hệ thống sẽ kiểm tra lại khi bạn gửi đề xuất.';
        syncCheckControls(null);
      }
    }, 300);
  }

  action.addEventListener('change', syncDescription);
  type.addEventListener('change', syncTargetHint);
  for (const field of [list, action, type]) field.addEventListener('change', scheduleTargetCheck);
  target.addEventListener('input', scheduleTargetCheck);
  window.addEventListener('pageshow', event => {
    if (event.persisted) scheduleTargetCheck();
  });
  proposal.addEventListener('input', event => {
    const field = event.target;
    clearError(field);
    if (['list_type', 'target_type', 'change_action'].includes(field.name)) {
      clearError(target);
    }
    if (field === action && action.value === 'REMOVE') {
      clearError(description);
    }
    if (['list_type', 'target_type', 'target_value'].includes(field.name)) {
      clearError(proposal.elements.conflict_ack);
    }
    if (summary && !proposal.querySelector('[aria-invalid="true"]')) {
      summary.hidden = true;
    }
  });

  syncDescription();
  syncTargetHint();
  const initialCheck = targetCheck.querySelector('[data-target-result]');
  syncCheckControls(initialCheck);
  if (!initialCheck && target.value.trim() && !target.hasAttribute('aria-invalid')) scheduleTargetCheck();
  proposal.querySelector('[aria-invalid="true"]')?.focus();
}
