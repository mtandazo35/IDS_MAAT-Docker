// Ejecuta los manejadores REALES (onmousedown / onclick) de cada capa de modal del panel.
// Uso: node guarda_capas.js <pares.json>   pares = [[nombre, onmousedown, onclick], ...]
// El navegador manda el click al elemento donde se SUELTA el raton: pulsar dentro de la caja
// y soltar fuera no puede cerrar el modal (se perderia lo escrito).
const fs = require('fs');
const pares = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
let fallos = 0;
function check(d, c) { console.log((c ? '  OK   ' : ' FALLA ') + d); if (!c) fallos++; }

function cierra(md, ck, pulsa, suelta) {
  const capa = { style: { display: 'flex' }, _dn: null };
  const caja = {};
  let llamada = false;
  // cualquier funcion global que llame el manejador (askNo, cerrar, closem...) cuenta como cerrar
  const g = new Proxy({}, {
    has: (_t, k) => typeof k === 'string' && k !== 'event' && !(k in globalThis),
    get: (_t, k) => (typeof k === 'symbol' ? undefined : function () { llamada = true; }),
  });
  const fmd = new Function('__g', 'event', 'with(__g){' + md + '}');
  const fck = new Function('__g', 'event', 'with(__g){' + ck + '}');
  fmd.call(capa, g, { target: pulsa === 'capa' ? capa : caja });
  fck.call(capa, g, { target: suelta === 'capa' ? capa : caja });
  return llamada || capa.style.display === 'none';
}

check('hay capas que probar (' + pares.length + ')', pares.length > 0);
for (const [nombre, md, ck] of pares) {
  check(nombre + ': pulsar dentro y soltar fuera NO cierra', !cierra(md, ck, 'caja', 'capa'));
  check(nombre + ': pulsar y soltar fuera SI cierra', cierra(md, ck, 'capa', 'capa'));
  check(nombre + ': pulsar y soltar dentro NO cierra', !cierra(md, ck, 'caja', 'caja'));
}
console.log('\n' + (fallos ? fallos + ' fallo(s)' : 'TODO OK'));
process.exit(fallos ? 1 : 0);
