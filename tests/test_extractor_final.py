"""Pruebas del consolidador del marcador de PEDIDO-EXTRACTOR-1."""

from scripts import extractor_final as ef


def _resumen(media: dict[str, float], por_tipo: dict[str, dict[str, float]]) -> dict:
    return {
        m: {
            "media": {"valor": media[m], "ic95": [0.0, 1.0]},
            "por_tipo": {t: {"valor": por_tipo[m].get(t, 0.0), "ic95": [0.0, 1.0]} for t in ef.TIPOS},
        }
        for m in ef.MODELOS
    }


def test_familia_se_queda_solo_si_sube_media_y_un_tipo_clave():
    familia = ef.FAMILIAS[0]
    antes = _resumen({"random_forest": 0.04, "xgboost": 0.12}, {"random_forest": {}, "xgboost": {}})
    sube = _resumen({"random_forest": 0.04, "xgboost": 0.20},
                    {"random_forest": {}, "xgboost": {"arp_spoofing": 0.30}})
    ev = ef.evaluar_familia(familia, antes, sube)
    assert ev["se_queda"] and ev["transferencia"]["arp_spoofing"]["xgboost"]["delta"] == 0.30
    assert not ev["prediccion"]["icmp_flood"]["cumplida"]
    # Sube la media pero ningún tipo clave llega a +0,10.
    plano = _resumen({"random_forest": 0.05, "xgboost": 0.13},
                     {"random_forest": {}, "xgboost": {"port_scan": 0.5}})
    assert not ef.evaluar_familia(familia, antes, plano)["se_queda"]


def test_criterio_parada_por_media_o_por_tres_tipos():
    base = _resumen({"random_forest": 0.04, "xgboost": 0.12}, {"random_forest": {}, "xgboost": {}})
    tres = _resumen({"random_forest": 0.05, "xgboost": 0.15},
                    {"random_forest": {}, "xgboost": {"arp_spoofing": 0.3, "port_scan": 0.25, "syn_flood": 0.26}})
    assert ef.criterio_parada(base, tres)["transferencia_lograda"]
    dos = _resumen({"random_forest": 0.05, "xgboost": 0.15},
                   {"random_forest": {}, "xgboost": {"arp_spoofing": 0.3, "port_scan": 0.25}})
    assert not ef.criterio_parada(base, dos)["transferencia_lograda"]
    media = _resumen({"random_forest": 0.20, "xgboost": 0.12}, {"random_forest": {}, "xgboost": {}})
    assert ef.criterio_parada(base, media)["por_modelo"]["random_forest"]["media_cumple"]
