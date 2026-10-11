/* ids-panel: comportamiento de las páginas. Sin alert() ni confirm(): modales propios ask()/aviso().
   La CSP solo permite este fichero ('self'); nada de scripts en línea. */
(function () {
  'use strict';

  /* ---- modales ------------------------------------------------------------------------------ */
  var askAccion = null;

  function abrir(m) {
    if (!m) { return; }
    m.hidden = false;
    var f = m.querySelector('input:not([type=hidden]),button.btn:not([disabled])');
    if (f) { f.focus(); }
  }
  function cerrar(m) { if (m) { m.hidden = true; } }

  function _ask(titulo, texto, ok, solo) {
    var m = document.getElementById('modal-ask');
    if (!m) { return; }
    document.getElementById('ask-tit').textContent = titulo || '';
    document.getElementById('ask-txt').textContent = texto || '';
    var b = document.getElementById('ask-ok');
    b.textContent = ok || 'Confirmar';
    document.getElementById('ask-no').hidden = !!solo;
    abrir(m);
    b.focus();
  }
  /* ask(): confirmación propia; `accion` se ejecuta solo si se pulsa el botón de confirmar */
  function ask(titulo, texto, ok, accion) { askAccion = accion || null; _ask(titulo, texto, ok, false); }
  /* aviso(): mensaje propio con un solo botón */
  function aviso(titulo, texto) { askAccion = null; _ask(titulo, texto, 'Entendido', true); }
  window.ask = ask;
  window.aviso = aviso;

  document.addEventListener('click', function (ev) {
    var t = ev.target;
    if (!(t instanceof Element)) { return; }
    if (t.id === 'ask-ok') {
      var a = askAccion; askAccion = null; cerrar(document.getElementById('modal-ask'));
      if (a) { a(); }
      return;
    }
    if (t.id === 'ask-no') { askAccion = null; cerrar(document.getElementById('modal-ask')); return; }
    var ab = t.closest('[data-abrir]');
    if (ab) { abrir(document.getElementById(ab.getAttribute('data-abrir'))); return; }
    if (t.closest('[data-cerrar]')) { cerrar(t.closest('.modal')); return; }
    if (t.classList.contains('modal')) { cerrar(t); return; }
    var cp = t.closest('[data-copiar]');
    if (cp) { copiar(cp); return; }
    var tm = t.closest('[data-cambiar-tema]');
    if (tm) { cambiarTema(); return; }
    var menu = document.querySelector('details.umenu[open]');
    if (menu && !menu.contains(t)) { menu.removeAttribute('open'); }
  });
  document.addEventListener('keydown', function (ev) {
    if (ev.key === 'Escape') {
      document.querySelectorAll('.modal').forEach(function (m) { cerrar(m); });
      askAccion = null;
    }
  });

  /* ---- formularios que piden confirmación ---------------------------------------------------- */
  document.addEventListener('submit', function (ev) {
    var f = ev.target;
    if (!(f instanceof HTMLFormElement)) { return; }
    if (f.hasAttribute('data-ask-titulo') && f.dataset.ok !== '1') {
      ev.preventDefault();
      ask(f.getAttribute('data-ask-titulo'), f.getAttribute('data-ask-texto'), f.getAttribute('data-ask-ok'),
          function () { f.dataset.ok = '1'; f.submit(); });
      return;
    }
    var nombre = f.getAttribute('data-confirmar-nombre');
    if (nombre !== null) {
      var i = f.querySelector('input[name=confirmar]');
      if (!i || i.value.trim() !== nombre) {
        ev.preventDefault();
        aviso('El nombre no coincide', 'Escribe exactamente el nombre del punto para borrarlo.');
      }
    }
  });
  document.addEventListener('input', function (ev) {
    var i = ev.target;
    if (!(i instanceof HTMLInputElement) || i.name !== 'confirmar') { return; }
    var f = i.form;
    var nombre = f && f.getAttribute('data-confirmar-nombre');
    var b = f && f.querySelector('button[type=submit]');
    if (b && nombre !== null) { b.disabled = i.value.trim() !== nombre; }
  });

  /* ---- copiar -------------------------------------------------------------------------------- */
  function copiar(boton) {
    var el = document.getElementById(boton.getAttribute('data-copiar'));
    if (!el) { return; }
    var texto = el.textContent;
    var hecho = function () {
      var antes = boton.textContent;
      boton.textContent = 'Copiado';
      setTimeout(function () { boton.textContent = antes; }, 1800);
    };
    var aMano = function () {
      var ta = document.createElement('textarea');
      ta.value = texto;
      ta.setAttribute('readonly', '');
      ta.className = 'fuera';
      document.body.appendChild(ta);
      ta.select();
      var ok = false;
      try { ok = document.execCommand('copy'); } catch (e) { ok = false; }
      document.body.removeChild(ta);
      if (ok) { hecho(); } else { aviso('No se pudo copiar', 'Selecciona el texto y cópialo a mano.'); }
    };
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(texto).then(hecho, aMano);
    } else {
      aMano();
    }
  }

  /* ---- tema ---------------------------------------------------------------------------------- */
  function cambiarTema() {
    var raiz = document.documentElement;
    var actual = raiz.getAttribute('data-tema');
    var oscuro = actual ? actual === 'oscuro' : window.matchMedia('(prefers-color-scheme: dark)').matches;
    var nuevo = oscuro ? 'claro' : 'oscuro';
    raiz.setAttribute('data-tema', nuevo);
    try { localStorage.setItem('ids-tema', nuevo); } catch (e) { /* sin almacenamiento */ }
  }

  /* ---- refresco de fragmentos (tabla de Puntos, avance de una operación) --------------------- */
  function terminado(el) { return !!el.querySelector('[data-terminada="1"]'); }

  document.querySelectorAll('[data-refrescar]').forEach(function (el) {
    var url = el.getAttribute('data-refrescar');
    var cada = parseInt(el.getAttribute('data-cada'), 10) || 15000;
    var ocupado = false;
    var id = null;
    if (terminado(el)) { return; }
    var tick = function () {
      if (ocupado || document.hidden && cada > 5000) { return; }
      ocupado = true;
      fetch(url, {credentials: 'same-origin', cache: 'no-store'}).then(function (r) {
        if (r.status === 401) { window.location.href = '/entrar'; return null; }
        return r.ok ? r.text() : null;
      }).then(function (txt) {
        if (txt !== null && txt !== undefined) {
          el.innerHTML = txt;
          if (terminado(el)) { clearInterval(id); }
        }
      }).catch(function () { /* red caída: se reintenta en el siguiente ciclo */ }).then(function () {
        ocupado = false;
      });
    };
    id = setInterval(tick, cada);
  });
})();
