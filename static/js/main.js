// WebSecure360 - Main JS
// Auto-dismiss flash messages after 5s
document.addEventListener('DOMContentLoaded', () => {
  document.querySelectorAll('.flash').forEach(el => {
    setTimeout(() => el.remove(), 5000);
  });
});
