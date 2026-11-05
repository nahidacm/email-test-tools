// Applied before first paint to avoid a flash of the wrong theme.
(function () {
  var t = null;
  try { t = localStorage.getItem('ett-theme'); } catch (e) {}
  if (!t) t = window.matchMedia && matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  document.documentElement.setAttribute('data-theme', t);
})();
