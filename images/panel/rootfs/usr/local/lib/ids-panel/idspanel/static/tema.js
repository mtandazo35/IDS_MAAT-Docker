/* ids-panel: aplica el tema elegido (claro/oscuro) antes de pintar; sin elección, el del sistema. */
(function () {
  try {
    var t = localStorage.getItem('ids-tema');
    if (t === 'claro' || t === 'oscuro') { document.documentElement.setAttribute('data-tema', t); }
  } catch (e) { /* sin almacenamiento: tema del sistema */ }
})();
