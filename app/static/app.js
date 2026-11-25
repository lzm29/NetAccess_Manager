const proposal = document.getElementById('proposal-form');
if (proposal) {
  const { change_action: action, target_type: type, target_value: target, description } = proposal.elements;
  const descriptionGroup = document.getElementById('description-group');
  const targetHint = document.getElementById('target-hint');
  const summary = document.getElementById('proposal-error-summary');

  function syncDescription() {
    const remove = action.value === 'REMOVE';
    descriptionGroup.hidden = remove;
    description.required = !remove;
    description.disabled = remove;
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

  action.addEventListener('change', syncDescription);
  type.addEventListener('change', syncTargetHint);
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
  proposal.querySelector('[aria-invalid="true"]')?.focus();
}
