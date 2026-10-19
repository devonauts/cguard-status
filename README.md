# Estado de CGuard Pro · copia de respaldo

Copia pública de la página de estado de CGuard Pro, fuera de nuestra red.

- **Página principal:** https://status.cguardpro.com (generada cada minuto en un servidor nuestro, independiente de la plataforma).
- **Esta copia:** https://devonauts.github.io/cguard-status/ — GitHub Pages. Carga los datos de la página principal y, si no responde, enseña lo que mide GitHub Actions desde fuera cada 5 minutos (`external.json`, rama `data`).

Qué hay aquí:

| Fichero | Qué es |
|---|---|
| `cguard-status-probe.py` | La sonda (la misma que corre en casa), en modo `--external`. Sólo biblioteca estándar. |
| `components.public.json` | Qué se vigila (sin direcciones de nuestra red). |
| `index.html` | La página, generada con `--export-page`. |
| `.github/workflows/probe.yml` | Cada 5 min: sondear, comprobar que la página principal está fresca, publicar `external.json`, avisar por Telegram. |

Regla de cada sonda: código 2xx/3xx **y** el marcador en el cuerpo **y** ninguna huella de página rota del borde. Un fallo se confirma a los 3 segundos.

Este repositorio se genera desde `infra/cguard-status/` del repositorio interno; no se edita a mano.
